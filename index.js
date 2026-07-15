// Servidor mínimo pra:
//   1) badge "quem está online com o RealityFPS" (já existia)
//   2) sistema de licença Pro
//
// Roda em qualquer host Node.js (Render, Railway, Fly.io, uma VPS, etc).
//
// Endpoints de badge (já existiam):
//   POST /heartbeat  { uuid }              -> marca esse UUID como online
//   POST /check       { uuids: [...] }      -> retorna quais desses UUIDs estão online
//
// Endpoints de licença:
//   POST /license/validate { key, uuid }         -> { valid, tier, reason? }
//   POST /license/generate { tier, note, maxActivations } + header x-admin-token
//                                                 -> { key }
//   GET  /license/list                            + header x-admin-token
//                                                 -> lista todas as keys (admin)
//   POST /license/revoke   { key }                + header x-admin-token
//
// IMPORTANTE: isso não é DRM à prova de crack (leia o comentário no
// LicenseManager.java do mod). É o suficiente pra vender pra uma comunidade
// de Discord de forma organizada: você gera uma key por venda, o comprador
// ativa no jogo, e cada key só ativa em N contas diferentes.
//
// -------------------------------------------------------------------------
// SOBRE O "A KEY FICA INVÁLIDA / DIZ QUE NÃO EXISTE MAIS" (leia isso!)
// -------------------------------------------------------------------------
// Na versão anterior desse backend, as licenças só existiam no arquivo local
// `backend/licenses.json`. Isso funciona bem numa VPS ou no Railway com um
// volume persistente, mas em MUITOS hosts "free" (Render free, containers
// efêmeros, etc.) o disco é apagado a cada:
//   - novo deploy,
//   - crash/reinício do processo,
//   - ou em alguns planos, todo "cold start" depois de dormir.
// Ou seja: você gera uma key, ela funciona, o host reinicia por qualquer
// motivo, o `licenses.json` volta vazio, e a mesma key passa a dar
// "key não existe" - mesmo sem você ter feito nada de errado.
//
// Duas formas de resolver, dos dois lados:
//   1) (Rápido/grátis) Usar um Postgres gratuito externo (Neon, Supabase,
//      Railway Postgres, ElephantSQL) e setar a variável de ambiente
//      DATABASE_URL. Esse arquivo detecta isso sozinho e passa a gravar lá
//      em vez do arquivo local - resolve o problema de vez, com storage de
//      verdade que sobrevive a redeploy/reinício.
//   2) (Mais simples, mas não à prova de reinício "vira e mexe") continuar
//      só com o arquivo local, e usar um host com disco persistente de
//      verdade (VPS com pm2, Railway com volume anexado). Ainda assim pode
//      perder tudo se você trocar de servidor sem migrar o arquivo.
// Sem DATABASE_URL configurada, o servidor cai automaticamente pro modo 1
// (arquivo), então nada quebra se você não configurar nada - mas o aviso
// acima é exatamente a causa mais provável do bug que você estava vendo.
// -------------------------------------------------------------------------

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

// ---------- Config ----------

// Defina isso como variável de ambiente no seu host (Render/Railway/etc).
// Sem essa variável configurada, os endpoints admin ficam desligados por segurança.
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';

const LICENSES_FILE = path.join(__dirname, 'licenses.json');

// ---------- Storage (arquivo local OU Postgres, dependendo de DATABASE_URL) ----------

const USE_POSTGRES = !!process.env.DATABASE_URL;
let pgPool = null;

/**
 * Normaliza uma key pra comparação: maiúsculas e sem espaço nas pontas.
 * Isso evita o caso clássico de "a key não existe" quando alguém digita ou
 * cola a key com letra minúscula ou espaço a mais - a key sempre é gerada
 * em maiúsculas, então normalizamos a entrada pra bater sempre.
 */
function normalizeKey(key) {
    return String(key || '').trim().toUpperCase();
}

async function initStorage() {
    if (USE_POSTGRES) {
        const { Pool } = require('pg');
        pgPool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: { rejectUnauthorized: false },
        });
        await pgPool.query(`
            CREATE TABLE IF NOT EXISTS licenses (
                key TEXT PRIMARY KEY,
                tier TEXT NOT NULL DEFAULT 'pro',
                note TEXT NOT NULL DEFAULT '',
                created_at BIGINT NOT NULL,
                expires_at BIGINT,
                max_activations INTEGER NOT NULL DEFAULT 1,
                activated_uuids JSONB NOT NULL DEFAULT '[]'::jsonb
            );
        `);
        // Migração segura pra quem já tinha o banco criado antes dessas colunas existirem
        // (CREATE TABLE IF NOT EXISTS não adiciona coluna em tabela que já existe).
        await pgPool.query(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS buyer_discord_id TEXT;`);
        await pgPool.query(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS notified_expiry BOOLEAN NOT NULL DEFAULT FALSE;`);
        await pgPool.query(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT FALSE;`);
        const { rows } = await pgPool.query('SELECT count(*)::int AS n FROM licenses');
        console.log(`[storage] Usando Postgres (DATABASE_URL configurada). ${rows[0].n} licença(s) carregada(s).`);
    } else {
        console.log('[storage] DATABASE_URL não configurada - usando backend/licenses.json local.');
        console.log('[storage] AVISO: em hosts com disco efêmero (ex: Render free) esse arquivo pode ');
        console.log('[storage] ser apagado a cada redeploy/reinício, fazendo keys válidas "sumirem".');
        const all = await fileReadAll();
        console.log(`[storage] ${Object.keys(all).length} licença(s) carregada(s) do arquivo local.`);
    }
}

// --- Implementação em arquivo local (fallback padrão) ---

function fileReadAllSync() {
    try {
        if (fs.existsSync(LICENSES_FILE)) {
            return JSON.parse(fs.readFileSync(LICENSES_FILE, 'utf8'));
        }
    } catch (e) {
        console.error('Não consegui ler licenses.json, começando do zero.', e);
    }
    return {};
}

async function fileReadAll() {
    return fileReadAllSync();
}

function fileWriteAllSync(licenses) {
    // Escrita atômica: grava num arquivo temporário e renomeia por cima do original.
    // Evita corromper o licenses.json se o processo morrer no meio da escrita.
    const tmp = LICENSES_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(licenses, null, 2));
    fs.renameSync(tmp, LICENSES_FILE);
}

async function storeGet(key) {
    key = normalizeKey(key);
    if (USE_POSTGRES) {
        const { rows } = await pgPool.query('SELECT * FROM licenses WHERE key = $1', [key]);
        if (!rows.length) return null;
        const r = rows[0];
        return {
            tier: r.tier,
            note: r.note,
            createdAt: Number(r.created_at),
            expiresAt: r.expires_at === null ? null : Number(r.expires_at),
            maxActivations: r.max_activations,
            activatedUuids: r.activated_uuids || [],
            buyerDiscordId: r.buyer_discord_id || null,
            notifiedExpiry: !!r.notified_expiry,
            revoked: !!r.revoked,
        };
    }
    const all = fileReadAllSync();
    return all[key] || null;
}

async function storeSet(key, license) {
    key = normalizeKey(key);
    if (USE_POSTGRES) {
        await pgPool.query(
            `INSERT INTO licenses (key, tier, note, created_at, expires_at, max_activations, activated_uuids, buyer_discord_id, notified_expiry, revoked)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (key) DO UPDATE SET
                tier = EXCLUDED.tier,
                note = EXCLUDED.note,
                expires_at = EXCLUDED.expires_at,
                max_activations = EXCLUDED.max_activations,
                activated_uuids = EXCLUDED.activated_uuids,
                buyer_discord_id = EXCLUDED.buyer_discord_id,
                notified_expiry = EXCLUDED.notified_expiry,
                revoked = EXCLUDED.revoked`,
            [key, license.tier, license.note, license.createdAt, license.expiresAt,
                license.maxActivations, JSON.stringify(license.activatedUuids),
                license.buyerDiscordId || null, !!license.notifiedExpiry, !!license.revoked]
        );
        return;
    }
    const all = fileReadAllSync();
    all[key] = license;
    fileWriteAllSync(all);
}

async function storeDelete(key) {
    key = normalizeKey(key);
    if (USE_POSTGRES) {
        const { rowCount } = await pgPool.query('DELETE FROM licenses WHERE key = $1', [key]);
        return rowCount > 0;
    }
    const all = fileReadAllSync();
    if (!all[key]) return false;
    delete all[key];
    fileWriteAllSync(all);
    return true;
}

async function storeAll() {
    if (USE_POSTGRES) {
        const { rows } = await pgPool.query('SELECT * FROM licenses');
        const out = {};
        for (const r of rows) {
            out[r.key] = {
                tier: r.tier,
                note: r.note,
                createdAt: Number(r.created_at),
                expiresAt: r.expires_at === null ? null : Number(r.expires_at),
                maxActivations: r.max_activations,
                activatedUuids: r.activated_uuids || [],
                buyerDiscordId: r.buyer_discord_id || null,
                notifiedExpiry: !!r.notified_expiry,
                revoked: !!r.revoked,
            };
        }
        return out;
    }
    return fileReadAllSync();
}

// ---------- Badge (já existia) ----------

const ONLINE_TIMEOUT_MS = 90 * 1000;
const lastSeen = new Map();
// FEATURE PRO: uuid -> último tier informado ("pro", "free", etc), pra exibir o selo pros outros
const lastTier = new Map();

app.post('/heartbeat', (req, res) => {
    const { uuid, tier } = req.body || {};
    if (typeof uuid !== 'string' || uuid.length < 10) {
        return res.status(400).json({ error: 'uuid inválido' });
    }
    lastSeen.set(uuid, Date.now());
    if (typeof tier === 'string') {
        lastTier.set(uuid, tier);
    }
    res.json({ ok: true });
});

app.post('/check', (req, res) => {
    const { uuids } = req.body || {};
    if (!Array.isArray(uuids)) {
        return res.status(400).json({ error: 'uuids deve ser uma lista' });
    }
    const now = Date.now();
    const online = uuids.filter((u) => {
        const t = lastSeen.get(u);
        return t !== undefined && (now - t) < ONLINE_TIMEOUT_MS;
    });
    const proUuids = online.filter((u) => lastTier.get(u) && lastTier.get(u) !== 'free');
    res.json({ online, proUuids });
});

setInterval(() => {
    const now = Date.now();
    for (const [uuid, t] of lastSeen.entries()) {
        if (now - t > ONLINE_TIMEOUT_MS) {
            lastSeen.delete(uuid);
            lastTier.delete(uuid);
        }
    }
}, 60 * 1000);

// ---------- Licença Pro ----------

function requireAdmin(req, res, next) {
    if (!ADMIN_TOKEN) {
        return res.status(503).json({ error: 'ADMIN_TOKEN não configurado no servidor' });
    }
    if (req.headers['x-admin-token'] !== ADMIN_TOKEN) {
        return res.status(401).json({ error: 'não autorizado' });
    }
    next();
}

function generateKey() {
    // formato: RFPS-XXXX-XXXX-XXXX (fácil de digitar/copiar no Discord)
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // sem O/0/I/1 pra evitar confusão
    const part = () => Array.from({ length: 4 }, () =>
        alphabet[crypto.randomInt(alphabet.length)]).join('');
    return `RFPS-${part()}-${part()}-${part()}`;
}

/**
 * Lógica de criação de uma licença, compartilhada entre o endpoint HTTP
 * /license/generate e o bot do Discord (pra não duplicar código nem precisar
 * o bot chamar o próprio servidor via HTTP com o ADMIN_TOKEN exposto).
 */
async function createLicense({ tier = 'pro', note = '', maxActivations = 1, expiresInDays = null, buyerDiscordId = null }) {
    let key;
    do {
        key = generateKey();
    } while (await storeGet(key)); // (nunca deve colidir, mas por garantia)

    const license = {
        tier,
        note,
        createdAt: Date.now(),
        expiresAt: expiresInDays ? Date.now() + expiresInDays * 24 * 60 * 60 * 1000 : null,
        maxActivations,
        activatedUuids: [],
        buyerDiscordId,
        notifiedExpiry: false,
        revoked: false,
    };
    await storeSet(key, license);
    return { key, ...license };
}

// Gera uma nova key. Chame isso você mesmo (via curl/Postman) toda vez que vender uma key no Discord.
app.post('/license/generate', requireAdmin, async (req, res) => {
    try {
        const { tier = 'pro', note = '', maxActivations = 1, expiresInDays = null, buyerDiscordId = null } = req.body || {};
        const result = await createLicense({ tier, note, maxActivations, expiresInDays, buyerDiscordId });
        res.json(result);
    } catch (e) {
        console.error('Erro em /license/generate', e);
        res.status(500).json({ error: 'erro interno ao gerar a key' });
    }
});

// Lista todas as keys (pra você administrar quem comprou o quê)
app.get('/license/list', requireAdmin, async (req, res) => {
    try {
        res.json(await storeAll());
    } catch (e) {
        console.error('Erro em /license/list', e);
        res.status(500).json({ error: 'erro interno ao listar keys' });
    }
});

// Revoga uma key (ex: chargeback, venda cancelada). Soft-revoke: fica marcada como
// revogada (não valida mais) mas continua contando nas estatísticas de /license/stats.
app.post('/license/revoke', requireAdmin, async (req, res) => {
    try {
        const { key } = req.body || {};
        if (!key) {
            return res.status(400).json({ error: 'key ausente' });
        }
        const lic = await storeGet(key);
        if (!lic) {
            return res.status(404).json({ error: 'key não encontrada' });
        }
        lic.revoked = true;
        await storeSet(key, lic);
        res.json({ ok: true });
    } catch (e) {
        console.error('Erro em /license/revoke', e);
        res.status(500).json({ error: 'erro interno ao revogar a key' });
    }
});

async function getLicenseStats() {
    const all = await storeAll();
    const now = Date.now();
    let total = 0, active = 0, expired = 0, revoked = 0, activationsUsed = 0, activationsTotal = 0;
    for (const lic of Object.values(all)) {
        total++;
        if (lic.revoked) {
            revoked++;
        } else if (lic.expiresAt && now > lic.expiresAt) {
            expired++;
        } else {
            active++;
        }
        activationsUsed += (lic.activatedUuids || []).length;
        activationsTotal += lic.maxActivations || 0;
    }
    return { total, active, expired, revoked, activationsUsed, activationsTotal };
}

// "Estoque": estatísticas gerais das licenças, pra você acompanhar suas vendas.
app.get('/license/stats', requireAdmin, async (req, res) => {
    try {
        res.json(await getLicenseStats());
    } catch (e) {
        console.error('Erro em /license/stats', e);
        res.status(500).json({ error: 'erro interno ao calcular estatísticas' });
    }
});

// Endpoint que o MOD chama pra validar a key do jogador
app.post('/license/validate', async (req, res) => {
    try {
        const { key, uuid } = req.body || {};
        if (typeof key !== 'string' || typeof uuid !== 'string' || !key.trim() || !uuid.trim()) {
            return res.status(400).json({ valid: false, reason: 'key ou uuid ausente' });
        }

        // Nunca aceita uuid "unknown": se aceitássemos, todo jogador cujo cliente não
        // conseguiu resolver o UUID (ex: conta não-premium mal configurada) compartilharia
        // essa MESMA identidade "unknown" e brigaria pela mesma vaga de ativação da key -
        // exatamente o tipo de coisa que faz uma key "parar de funcionar do nada" pra
        // outra pessoa sem nenhum motivo aparente.
        if (uuid.trim().toLowerCase() === 'unknown') {
            return res.json({ valid: false, reason: 'uuid não identificado (conta inválida no cliente)' });
        }

        const lic = await storeGet(key);
        if (!lic) {
            return res.json({ valid: false, reason: 'key não existe' });
        }

        if (lic.revoked) {
            return res.json({ valid: false, reason: 'key revogada' });
        }

        if (lic.expiresAt && Date.now() > lic.expiresAt) {
            return res.json({ valid: false, reason: 'key expirada' });
        }

        const alreadyActivated = lic.activatedUuids.includes(uuid);
        if (!alreadyActivated) {
            if (lic.activatedUuids.length >= lic.maxActivations) {
                return res.json({ valid: false, reason: 'limite de ativações atingido pra essa key' });
            }
            lic.activatedUuids = [...lic.activatedUuids, uuid];
            await storeSet(key, lic);
        }

        res.json({ valid: true, tier: lic.tier });
    } catch (e) {
        console.error('Erro em /license/validate', e);
        res.status(500).json({ valid: false, reason: 'erro interno do servidor' });
    }
});

/**
 * Retorna as licenças que vencem dentro de `daysAhead` dias, ainda não notificadas,
 * não revogadas, com um `buyerDiscordId` conhecido (só dá pra avisar quem o bot sabe
 * quem é - keys geradas via curl/Postman sem passar `comprador` não tem como avisar).
 */
async function getExpiringLicenses(daysAhead) {
    const all = await storeAll();
    const now = Date.now();
    const windowMs = daysAhead * 24 * 60 * 60 * 1000;
    const result = [];
    for (const [key, lic] of Object.entries(all)) {
        if (lic.revoked || lic.notifiedExpiry || !lic.expiresAt || !lic.buyerDiscordId) {
            continue;
        }
        if (lic.expiresAt > now && lic.expiresAt - now <= windowMs) {
            result.push({ key, ...lic });
        }
    }
    return result;
}

async function markExpiryNotified(key) {
    const lic = await storeGet(key);
    if (lic) {
        lic.notifiedExpiry = true;
        await storeSet(key, lic);
    }
}

const PORT = process.env.PORT || 3000;
initStorage()
    .then(() => {
        app.listen(PORT, () => console.log(`RealityFPS backend rodando na porta ${PORT}`));
        // Bot do Discord (opcional): só sobe se DISCORD_TOKEN estiver configurado.
        // Veja backend/DISCORD_BOT.md pra configurar os comandos.
        require('./discordBot').initDiscordBot({
            createLicense,
            storeAll,
            storeGet,
            storeSet,
            getExpiringLicenses,
            markExpiryNotified,
            getLicenseStats,
        });
    })
    .catch((e) => {
        console.error('Falha ao iniciar o storage, o servidor NÃO vai subir:', e);
        process.exit(1);
    });
