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
// Limite de tamanho no body: evita que alguém mande um payload gigante só pra gastar
// CPU/memória do processo (o mod nunca manda mais que uma keyzinha + um UUID).
app.use(express.json({ limit: '10kb' }));
// Necessário no Render/Railway/etc (o app fica atrás de um proxy reverso) pra req.ip
// devolver o IP real do cliente em vez do IP interno do proxy - sem isso, o rate
// limiter abaixo trataria TODO mundo como se fosse o mesmo IP.
app.set('trust proxy', 1);

// ---------- Config ----------

// Defina isso como variável de ambiente no seu host (Render/Railway/etc).
// Sem essa variável configurada, os endpoints admin ficam desligados por segurança.
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';

// Segredo usado pra ASSINAR (HMAC-SHA256) cada resposta de /license/validate, pra o mod
// conseguir confirmar que a resposta veio mesmo deste backend (e não de um servidor falso
// que o jogador apontou via config editado à mão). Tem que ser EXATAMENTE o mesmo valor
// que está em SIGNING_SECRET no LicenseManager.java do mod - se um dos dois lados mudar
// sem o outro, toda validação passa a falhar por assinatura inválida.
const DEFAULT_SECRET_PLACEHOLDER = 'TROQUE_ISTO_openssl_rand_hex_32_ANTES_DE_VENDER';
const SIGNING_SECRET = process.env.LICENSE_SIGNING_SECRET || DEFAULT_SECRET_PLACEHOLDER;
// FALHA FECHADA (em vez de só avisar): se ninguém configurou LICENSE_SIGNING_SECRET,
// esse valor placeholder está público neste arquivo-fonte - ou seja, QUALQUER PESSOA
// com acesso a este repositório (ou que veja esse arquivo em algum vazamento/print)
// consegue assinar respostas falsas de "licença válida" sozinha, sem nunca precisar
// decompilar nada. Antes, isso só gerava um aviso no console e o servidor continuava
// no ar assinando com esse valor público - fácil de passar despercebido num deploy
// apressado. Agora o processo nem sobe: é melhor a loja parar (erro óbvio, fácil de
// notar e corrigir) do que vender licenças "seguras" que na verdade não protegem nada.
if (SIGNING_SECRET === DEFAULT_SECRET_PLACEHOLDER) {
    console.error('[segurança] LICENSE_SIGNING_SECRET não configurado - o valor padrão do template');
    console.error('[segurança] é PÚBLICO (está no código-fonte) e não protege nada. Gere um valor forte');
    console.error('[segurança] com `openssl rand -hex 32`, configure como variável de ambiente');
    console.error('[segurança] LICENSE_SIGNING_SECRET aqui, gere o array correspondente com');
    console.error('[segurança] tools/encode_signing_secret.py e cole em LicenseManager.java no mod,');
    console.error('[segurança] e recompile o mod. Recusando iniciar o servidor até isso ser corrigido.');
    process.exit(1);
}

/** Assina os campos de uma resposta de validação. Formato tem que bater com o LicenseManager.java. */
function signValidation(key, uuid, tier, timestampSeconds) {
    return crypto.createHmac('sha256', SIGNING_SECRET)
        .update(`${key}|${uuid}|${tier}|${timestampSeconds}`)
        .digest('base64');
}

/** Comparação em tempo constante pra tokens/segredos - evita vazar por timing quantos bytes bateram. */
function timingSafeStringEqual(a, b) {
    const ba = Buffer.from(String(a ?? ''), 'utf8');
    const bb = Buffer.from(String(b ?? ''), 'utf8');
    if (ba.length !== bb.length) {
        // ainda assim consome um tempo comparável, pra não vazar "tamanho errado" tão rápido
        crypto.timingSafeEqual(ba, ba);
        return false;
    }
    return crypto.timingSafeEqual(ba, bb);
}

// ---------- Rate limiting simples, em memória, sem dependência externa ----------
//
// Não precisa ser sofisticado: só existe pra impedir que alguém fique martelando
// /license/validate (tentando adivinhar keys por força bruta) ou /heartbeat e /check
// (spam) sem limite nenhum. Uma janela deslizante por IP é suficiente pro volume de
// uma comunidade de Discord - não tente usar isso como proteção de DDoS de verdade
// (pra isso, use algo na frente como Cloudflare).
const rateBuckets = new Map(); // ip+route -> [timestamps]
function rateLimit(routeName, maxRequests, windowMs) {
    return (req, res, next) => {
        const key = `${routeName}:${req.ip}`;
        const now = Date.now();
        const timestamps = (rateBuckets.get(key) || []).filter((t) => now - t < windowMs);
        if (timestamps.length >= maxRequests) {
            return res.status(429).json({ error: 'muitas requisições, tenta de novo daqui a pouco' });
        }
        timestamps.push(now);
        rateBuckets.set(key, timestamps);
        next();
    };
}
// Limpeza periódica pra não vazar memória com IPs antigos
setInterval(() => {
    const now = Date.now();
    for (const [key, timestamps] of rateBuckets.entries()) {
        const kept = timestamps.filter((t) => now - t < 10 * 60 * 1000);
        if (kept.length === 0) rateBuckets.delete(key);
        else rateBuckets.set(key, kept);
    }
}, 5 * 60 * 1000);

// ---------- Trava por KEY contra força bruta distribuída entre vários IPs ----------
//
// O rateLimit acima é por IP: protege contra UM atacante martelando de UM lugar,
// mas não contra alguém tentando adivinhar uma key específica (ou testando uma
// lista de keys vazadas) usando muitos IPs diferentes (proxies, botnet, VPN
// trocando toda hora) - cada IP individualmente fica bem abaixo do limite de 20/min,
// mas a KEY em si está recebendo centenas de tentativas. Aqui contamos tentativas
// FALHAS por key normalizada, não por IP, então não importa de onde elas vêm.
const FAILED_ATTEMPTS_LIMIT = 8;
const FAILED_ATTEMPTS_WINDOW_MS = 10 * 60 * 1000;
const KEY_LOCKOUT_MS = 15 * 60 * 1000;
const failedAttemptsByKey = new Map(); // normalizedKey -> [timestamps]
const lockedKeysUntil = new Map();     // normalizedKey -> epoch ms até quando fica travada

function isKeyLocked(normalizedKey) {
    const until = lockedKeysUntil.get(normalizedKey);
    if (!until) return false;
    if (Date.now() >= until) {
        lockedKeysUntil.delete(normalizedKey);
        return false;
    }
    return true;
}

/** Chame isso sempre que uma validação de key falhar (key errada, revogada, etc). */
function recordFailedAttempt(normalizedKey) {
    const now = Date.now();
    const attempts = (failedAttemptsByKey.get(normalizedKey) || []).filter(
        (t) => now - t < FAILED_ATTEMPTS_WINDOW_MS
    );
    attempts.push(now);
    failedAttemptsByKey.set(normalizedKey, attempts);
    if (attempts.length >= FAILED_ATTEMPTS_LIMIT && !lockedKeysUntil.has(normalizedKey)) {
        lockedKeysUntil.set(normalizedKey, now + KEY_LOCKOUT_MS);
        // Log só na hora que a trava É ACIONADA (não a cada tentativa depois disso, senão
        // vira spam de log) - isso é o sinal mais barato que você tem de "alguém está testando
        // uma key roubada/vazada ou tentando adivinhar uma". Vale a pena olhar esses logs de
        // vez em quando (ou, no futuro, mandar pra um webhook do Discord) e, se aparecer muito
        // pra uma key específica, considerar revogá-la e avisar o dono de verdade dela.
        console.warn(`[abuso] key travada por ${KEY_LOCKOUT_MS / 60000}min após ${attempts.length} falhas em ${FAILED_ATTEMPTS_WINDOW_MS / 60000}min (prefixo: ${normalizedKey.slice(0, 8)}...)`);
    }
}

/** Chame isso quando uma validação passar - reseta o contador de falhas dessa key. */
function clearFailedAttempts(normalizedKey) {
    failedAttemptsByKey.delete(normalizedKey);
}

// ---------- Detecção de key compartilhada/revendida: muitas keys distintas pro mesmo UUID ----------
//
// Um jogador legítimo normalmente usa 1 key (a dele) - talvez 2 se comprou de novo depois de
// perder acesso à antiga. Se o MESMO uuid de Minecraft aparece validando várias keys DIFERENTES
// num período curto, é um padrão típico de: (a) alguém testando uma lista de keys vazadas nesse
// personagem, ou (b) um "revendedor" compartilhando várias keys que ele mesmo gerencia. Isso é só
// um log informativo (threshold alto de propósito, pra não alarmar por coincidência tipo family
// share de PC) - não bloqueia nada sozinho, é pra você revisar manualmente.
const DISTINCT_KEYS_PER_UUID_WINDOW_MS = 24 * 60 * 60 * 1000; // 24h
const DISTINCT_KEYS_PER_UUID_ALERT_THRESHOLD = 5;
const keysSeenByUuid = new Map(); // uuid -> Map(normalizedKey -> lastSeenTimestamp)

function recordKeyUsageForUuid(uuid, normalizedKey) {
    if (!uuid) return;
    const now = Date.now();
    const seen = keysSeenByUuid.get(uuid) || new Map();
    seen.set(normalizedKey, now);
    // limpa entradas velhas dessa uuid antes de contar
    for (const [k, t] of seen.entries()) {
        if (now - t > DISTINCT_KEYS_PER_UUID_WINDOW_MS) seen.delete(k);
    }
    keysSeenByUuid.set(uuid, seen);
    if (seen.size === DISTINCT_KEYS_PER_UUID_ALERT_THRESHOLD) {
        // dispara só uma vez quando cruza o threshold, não de novo a cada key nova depois disso
        console.warn(`[abuso] uuid ${uuid} validou ${seen.size} keys diferentes nas últimas 24h - possível key farm/revenda, vale revisar`);
    }
}

// Limpeza periódica (mesma ideia do rateBuckets acima)
setInterval(() => {
    const now = Date.now();
    for (const [uuid, seen] of keysSeenByUuid.entries()) {
        for (const [k, t] of seen.entries()) {
            if (now - t > DISTINCT_KEYS_PER_UUID_WINDOW_MS) seen.delete(k);
        }
        if (seen.size === 0) keysSeenByUuid.delete(uuid);
    }
}, 5 * 60 * 1000);

// Limpeza periódica (mesma ideia do rateBuckets acima)
setInterval(() => {
    const now = Date.now();
    for (const [key, timestamps] of failedAttemptsByKey.entries()) {
        const kept = timestamps.filter((t) => now - t < FAILED_ATTEMPTS_WINDOW_MS);
        if (kept.length === 0) failedAttemptsByKey.delete(key);
        else failedAttemptsByKey.set(key, kept);
    }
    for (const [key, until] of lockedKeysUntil.entries()) {
        if (now >= until) lockedKeysUntil.delete(key);
    }
}, 5 * 60 * 1000);

// ---------- Trava por key (evita corrida de ativação) ----------
//
// BUG CORRIGIDO: antes, /license/validate fazia "lê a licença -> confere se ainda cabe
// uma ativação -> grava de volta com o UUID novo" em passos separados (storeGet, depois
// storeSet). Se duas requisições da MESMA key chegassem quase ao mesmo tempo (ex: dois
// PCs diferentes usando a key vazada, ou só uma reconexão rápida), as duas podiam ler o
// mesmo estado "ainda cabe 1 ativação" ANTES de qualquer uma escrever - e as duas
// passavam, estourando o limite de ativações da key. Serializamos por key aqui.
const keyLocks = new Map();
function withKeyLock(key, fn) {
    const prev = keyLocks.get(key) || Promise.resolve();
    const run = prev.then(fn, fn);
    // Guarda a promise já "resolvida" (sem propagar erro pra próxima da fila) só pra
    // encadear a ordem - o erro de verdade continua sendo devolvido pra quem chamou "run".
    keyLocks.set(key, run.then(() => {}, () => {}));
    return run;
}

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

// ---------- Health / keep-alive ----------
//
// PRA QUE SERVE ISSO: no plano free do Render, o serviço "dorme" depois de ~15 minutos
// sem receber NENHUMA requisição HTTP de fora. Quando isso acontece, o processo Node
// inteiro para - e como o bot do Discord roda dentro desse MESMO processo, ele também
// cai junto (é por isso que o bot "fica off toda hora": não é o bot que trava, é o
// Render que desliga o servidor inteiro por inatividade).
//
// A solução é fazer alguma requisição externa bater nesse endpoint de tempos em tempos
// (menos de 15 min), pra o Render sempre ver "tráfego recente" e nunca dormir. Um jeito
// grátis: cria uma conta em https://uptimerobot.com, adiciona um monitor HTTP(s) apontando
// pra "https://SEU-BACKEND.onrender.com/health" com intervalo de 5 minutos. Isso mantém o
// servidor (e o bot) online 24/7 sem custar nada.
app.get('/health', (req, res) => {
    res.json({ ok: true, uptimeSeconds: Math.round(process.uptime()) });
});

// ---------- Badge (já existia) ----------

const ONLINE_TIMEOUT_MS = 90 * 1000;
const lastSeen = new Map();

// BUG DE SEGURANÇA CORRIGIDO: antes, o selo "★ Pro" mostrado pros OUTROS jogadores vinha
// de "lastTier", preenchido com o campo "tier" que o PRÓPRIO cliente manda no /heartbeat -
// ou seja, o backend confiava cegamente na palavra do cliente sobre se ele é Pro ou não.
// Qualquer client modificado (ou até um script simples imitando um heartbeat HTTP) podia
// mandar tier: "pro" e exibir a estrela pra todo mundo sem nunca ter validado key nenhuma.
// Isso não desbloqueava nada de verdade pra quem fez isso (as features Pro continuam
// gated por LicenseManager.isPro(), que é validado à parte via /license/validate assinado),
// mas ainda assim é uma mentira visual pros outros jogadores - o selo devia significar algo.
// Agora o selo só é concedido a partir de uma validação de licença REAL e bem-sucedida
// (a mesma chamada assinada que o LicenseManager.java faz), guardada aqui no servidor -
// o corpo do /heartbeat não tem mais nenhuma influência sobre quem aparece como Pro.
const PRO_BADGE_TTL_MS = 90 * 60 * 1000; // um pouco mais que o intervalo de revalidação (60min)
const verifiedProUuids = new Map(); // uuid -> expiresAt (ms) de uma validação Pro recente e real

app.post('/heartbeat', rateLimit('heartbeat', 20, 60 * 1000), (req, res) => {
    const { uuid } = req.body || {};
    if (typeof uuid !== 'string' || uuid.length < 10) {
        return res.status(400).json({ error: 'uuid inválido' });
    }
    lastSeen.set(uuid, Date.now());
    // O campo "tier" que o mod manda aqui é só informativo pra debug - NÃO é mais usado
    // pra decidir o selo Pro (ver comentário acima de verifiedProUuids).
    res.json({ ok: true });
});

app.post('/check', rateLimit('check', 30, 60 * 1000), (req, res) => {
    const { uuids } = req.body || {};
    if (!Array.isArray(uuids)) {
        return res.status(400).json({ error: 'uuids deve ser uma lista' });
    }
    // Limite de tamanho: sem isso, alguém podia mandar uma lista com milhares de UUIDs
    // fabricados num único request e forçar o servidor a fazer um filter() gigante à toa.
    if (uuids.length > 200) {
        return res.status(400).json({ error: 'lista de uuids grande demais (máximo 200)' });
    }
    const now = Date.now();
    const online = uuids.filter((u) => {
        const t = lastSeen.get(u);
        return t !== undefined && (now - t) < ONLINE_TIMEOUT_MS;
    });
    const proUuids = online.filter((u) => {
        const expiresAt = verifiedProUuids.get(u);
        return expiresAt !== undefined && expiresAt > now;
    });
    res.json({ online, proUuids });
});

setInterval(() => {
    const now = Date.now();
    for (const [uuid, t] of lastSeen.entries()) {
        if (now - t > ONLINE_TIMEOUT_MS) {
            lastSeen.delete(uuid);
        }
    }
    for (const [uuid, expiresAt] of verifiedProUuids.entries()) {
        if (now > expiresAt) {
            verifiedProUuids.delete(uuid);
        }
    }
}, 60 * 1000);

// ---------- Licença Pro ----------

function requireAdmin(req, res, next) {
    if (!ADMIN_TOKEN) {
        return res.status(503).json({ error: 'ADMIN_TOKEN não configurado no servidor' });
    }
    if (!timingSafeStringEqual(req.headers['x-admin-token'], ADMIN_TOKEN)) {
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
async function createLicense({ tier = 'pro', note = '', maxActivations = 1, expiresInDays = null, expiresInMinutes = null, buyerDiscordId = null }) {
    let key;
    do {
        key = generateKey();
    } while (await storeGet(key)); // (nunca deve colidir, mas por garantia)

    // Minutos tem prioridade sobre dias se os dois vierem preenchidos (não deveria
    // acontecer normalmente, mas assim o comportamento fica previsível em vez de somar).
    let expiresAt = null;
    if (expiresInMinutes) {
        expiresAt = Date.now() + expiresInMinutes * 60 * 1000;
    } else if (expiresInDays) {
        expiresAt = Date.now() + expiresInDays * 24 * 60 * 60 * 1000;
    }

    const license = {
        tier,
        note,
        createdAt: Date.now(),
        expiresAt,
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
app.post('/license/generate', rateLimit('admin', 60, 60 * 1000), requireAdmin, async (req, res) => {
    try {
        const { tier = 'pro', note = '', maxActivations = 1, expiresInDays = null, expiresInMinutes = null, buyerDiscordId = null } = req.body || {};

        // Validação básica de entrada - isso aqui só é chamado por você mesmo (protegido por
        // ADMIN_TOKEN), mas validar mesmo assim evita gerar uma licença "quebrada" por engano
        // (ex: maxActivations negativo, ou um número gigante digitado errado sem querer).
        if (typeof tier !== 'string' || !tier.trim() || tier.length > 32) {
            return res.status(400).json({ error: 'tier inválido' });
        }
        if (!Number.isInteger(maxActivations) || maxActivations < 1 || maxActivations > 1000) {
            return res.status(400).json({ error: 'maxActivations deve ser um inteiro entre 1 e 1000' });
        }
        if (expiresInDays !== null && (!Number.isFinite(expiresInDays) || expiresInDays <= 0 || expiresInDays > 3650)) {
            return res.status(400).json({ error: 'expiresInDays inválido' });
        }
        if (expiresInMinutes !== null && (!Number.isFinite(expiresInMinutes) || expiresInMinutes <= 0)) {
            return res.status(400).json({ error: 'expiresInMinutes inválido' });
        }
        if (typeof note !== 'string' || note.length > 500) {
            return res.status(400).json({ error: 'note inválida (máximo 500 caracteres)' });
        }

        const result = await createLicense({ tier: tier.trim(), note, maxActivations, expiresInDays, expiresInMinutes, buyerDiscordId });
        res.json(result);
    } catch (e) {
        console.error('Erro em /license/generate', e);
        res.status(500).json({ error: 'erro interno ao gerar a key' });
    }
});

// Lista todas as keys (pra você administrar quem comprou o quê)
app.get('/license/list', rateLimit('admin', 60, 60 * 1000), requireAdmin, async (req, res) => {
    try {
        res.json(await storeAll());
    } catch (e) {
        console.error('Erro em /license/list', e);
        res.status(500).json({ error: 'erro interno ao listar keys' });
    }
});

// Revoga uma key (ex: chargeback, venda cancelada). Soft-revoke: fica marcada como
// revogada (não valida mais) mas continua contando nas estatísticas de /license/stats.
app.post('/license/revoke', rateLimit('admin', 60, 60 * 1000), requireAdmin, async (req, res) => {
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
app.get('/license/stats', rateLimit('admin', 60, 60 * 1000), requireAdmin, async (req, res) => {
    try {
        res.json(await getLicenseStats());
    } catch (e) {
        console.error('Erro em /license/stats', e);
        res.status(500).json({ error: 'erro interno ao calcular estatísticas' });
    }
});

// Endpoint que o MOD chama pra validar a key do jogador
app.post('/license/validate', rateLimit('validate', 20, 60 * 1000), async (req, res) => {
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

        const normalizedKey = normalizeKey(key);

        // Key travada por excesso de tentativas falhas recentes (ver seção "Trava por KEY"
        // acima) - responde igual a uma key inválida comum, sem entrar em detalhe de "está
        // travada por força bruta" (não queremos ensinar pra quem está testando keys que
        // existe esse mecanismo, nem quando ele foi acionado).
        if (isKeyLocked(normalizedKey)) {
            return res.json({ valid: false, reason: 'key não existe' });
        }

        // Lê + confere o limite de ativações + grava tudo dentro da mesma trava por key,
        // pra duas requisições concorrentes com a mesma key não conseguirem "passar" juntas
        // do limite de ativações (ver comentário na definição de withKeyLock acima).
        const result = await withKeyLock(normalizedKey, async () => {
            const lic = await storeGet(normalizedKey);
            if (!lic) {
                return { valid: false, reason: 'key não existe' };
            }
            if (lic.revoked) {
                return { valid: false, reason: 'key revogada' };
            }
            if (lic.expiresAt && Date.now() > lic.expiresAt) {
                return { valid: false, reason: 'key expirada' };
            }

            const alreadyActivated = lic.activatedUuids.includes(uuid);
            if (!alreadyActivated) {
                if (lic.activatedUuids.length >= lic.maxActivations) {
                    return { valid: false, reason: 'limite de ativações atingido pra essa key' };
                }
                lic.activatedUuids = [...lic.activatedUuids, uuid];
                await storeSet(normalizedKey, lic);
            }
            return { valid: true, tier: lic.tier };
        });

        if (!result.valid) {
            recordFailedAttempt(normalizedKey);
            return res.json(result);
        }
        clearFailedAttempts(normalizedKey);
        recordKeyUsageForUuid(uuid, normalizedKey);

        // Alimenta o selo "★ Pro" (badge) com uma validação REAL - ver comentário em
        // verifiedProUuids, lá em cima na seção de badge. Só entra aqui quem passou pela
        // validação de key de verdade (com todos os checks de revogação/expiração/limite
        // de ativação acima), nunca a partir do que o cliente diz por conta própria.
        if (result.tier && result.tier !== 'free') {
            verifiedProUuids.set(uuid, Date.now() + PRO_BADGE_TTL_MS);
        }

        // Assina a resposta (HMAC-SHA256) com SIGNING_SECRET, pra o mod conseguir confirmar
        // que essa resposta "valid: true" veio mesmo deste backend (ver LicenseManager.java).
        const ts = Math.floor(Date.now() / 1000);
        const sig = signValidation(normalizedKey, uuid, result.tier, ts);
        res.json({ valid: true, tier: result.tier, ts, sig });
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
