// Bot de Discord opcional. Comandos:
//   /gerarkey    - gera uma key Pro (restrito)
//   /revogarkey  - revoga uma key (restrito)
//   /estoque     - estatísticas de vendas (restrito)
//   /loja        - mostra o catálogo de produtos pros clientes (público)
//
// Também manda um log de vendas num canal (opcional) e lembra automaticamente
// quem comprou quando a key dele está perto de vencer (opcional).
//
// Só é ativado se DISCORD_TOKEN estiver configurado - sem ela, esse arquivo
// nem é carregado (veja o fim do index.js) e o resto do backend continua
// funcionando normal. Setup completo: backend/DISCORD_BOT.md.

const {
    Client,
    GatewayIntentBits,
    REST,
    Routes,
    SlashCommandBuilder,
    EmbedBuilder,
    PermissionFlagsBits,
} = require('discord.js');

function parseIdList(value) {
    return (value || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
}

/**
 * Catálogo da loja. Configurável via variável de ambiente SHOP_ITEMS (JSON), ex:
 *   SHOP_ITEMS=[{"name":"Pro Vitalício","price":"R$ 15","desc":"Todas as features Pro, pra sempre."},{"name":"Pro Mensal","price":"R$ 6/mês","desc":"Renovação manual todo mês."}]
 * Sem configurar, usa um catálogo de exemplo genérico.
 */
function loadShopItems() {
    const raw = process.env.SHOP_ITEMS;
    if (!raw) {
        return [
            { name: 'RealityFPS Pro - Vitalício', price: 'defina SHOP_ITEMS no .env', desc: 'Configure o catálogo real no backend (veja DISCORD_BOT.md).' },
        ];
    }
    try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
        console.error('[discord-bot] SHOP_ITEMS não é um JSON válido, usando catálogo vazio.', e.message);
        return [];
    }
}

/**
 * Inicializa o bot. Recebe as funções do index.js (mesmo processo, sem HTTP interno).
 */
function initDiscordBot({ createLicense, storeGet, storeSet, getExpiringLicenses, markExpiryNotified, getLicenseStats }) {
    const token = process.env.DISCORD_TOKEN;
    if (!token) {
        return; // bot desligado - nada a fazer
    }

    const clientId = process.env.DISCORD_CLIENT_ID;
    const guildId = process.env.DISCORD_GUILD_ID; // opcional, mas recomendado (comando aparece na hora)
    const allowedRoleId = process.env.DISCORD_ALLOWED_ROLE_ID; // opcional
    const allowedUserIds = parseIdList(process.env.DISCORD_ALLOWED_USER_IDS); // opcional
    const salesLogChannelId = process.env.SALES_LOG_CHANNEL_ID; // opcional
    const expiryReminderDays = Number(process.env.EXPIRY_REMINDER_DAYS || 3);
    const expiryCheckIntervalHours = Number(process.env.EXPIRY_CHECK_INTERVAL_HOURS || 6);

    if (!clientId) {
        console.error('[discord-bot] DISCORD_TOKEN configurado mas DISCORD_CLIENT_ID não - bot não vai subir.');
        return;
    }

    const commands = [
        new SlashCommandBuilder()
            .setName('gerarkey')
            .setDescription('Gera uma nova key Pro do RealityFPS')
            .addStringOption((opt) =>
                opt.setName('nota').setDescription('Quem comprou / referência').setRequired(false))
            .addIntegerOption((opt) =>
                opt.setName('ativacoes').setDescription('Em quantas contas essa key pode ser usada (padrão: 1)').setMinValue(1).setRequired(false))
            .addIntegerOption((opt) =>
                opt.setName('dias').setDescription('Expira em quantos dias (deixe vazio pra vitalícia)').setMinValue(1).setRequired(false))
            .addUserOption((opt) =>
                opt.setName('comprador').setDescription('Se preenchido, o bot manda a key por DM e avisa antes de vencer').setRequired(false)),
        new SlashCommandBuilder()
            .setName('revogarkey')
            .setDescription('Revoga uma key (ex: chargeback, venda cancelada)')
            .addStringOption((opt) =>
                opt.setName('key').setDescription('A key a revogar (ex: RFPS-AB3D-92XZ-77QK)').setRequired(true)),
        new SlashCommandBuilder()
            .setName('estoque')
            .setDescription('Mostra estatísticas de vendas/licenças (restrito)'),
        new SlashCommandBuilder()
            .setName('verkey')
            .setDescription('Mostra detalhes de uma key: quem já ativou e o nick da conta no Minecraft (restrito)')
            .addStringOption((opt) =>
                opt.setName('key').setDescription('A key a consultar (ex: RFPS-AB3D-92XZ-77QK)').setRequired(true)),
        new SlashCommandBuilder()
            .setName('loja')
            .setDescription('Mostra o catálogo de produtos do RealityFPS Pro'),
    ];

    const rest = new REST({ version: '10' }).setToken(token);
    const body = commands.map((c) => c.toJSON());
    const registerPromise = guildId
        ? rest.put(Routes.applicationGuildCommands(clientId, guildId), { body })
        : rest.put(Routes.applicationCommands(clientId), { body });

    registerPromise
        .then(() => console.log(`[discord-bot] Comandos registrados ${guildId ? '(guild ' + guildId + ')' : '(global, pode levar ~1h pra aparecer)'}.`))
        .catch((e) => console.error('[discord-bot] Falha ao registrar comandos:', e));

    const client = new Client({ intents: [GatewayIntentBits.Guilds] });

    client.once('ready', () => {
        console.log(`[discord-bot] Conectado como ${client.user.tag}.`);
        // Checa lembretes de expiração periodicamente (e uma vez já ao subir).
        checkExpiringLicenses(client, { getExpiringLicenses, markExpiryNotified, expiryReminderDays });
        setInterval(
            () => checkExpiringLicenses(client, { getExpiringLicenses, markExpiryNotified, expiryReminderDays }),
            expiryCheckIntervalHours * 60 * 60 * 1000
        );
    });

    function isAuthorized(interaction) {
        // Sem nenhuma restrição configurada, exige permissão de Administrador no
        // servidor por segurança (não deixa qualquer membro gerar/revogar key de graça).
        if (!allowedRoleId && allowedUserIds.length === 0) {
            return interaction.memberPermissions?.has(PermissionFlagsBits.Administrator) ?? false;
        }
        if (allowedUserIds.includes(interaction.user.id)) {
            return true;
        }
        if (allowedRoleId && interaction.member?.roles?.cache?.has(allowedRoleId)) {
            return true;
        }
        return false;
    }

    async function denyIfNotAuthorized(interaction) {
        if (isAuthorized(interaction)) {
            return false;
        }
        await interaction.reply({
            content: '🚫 Você não tem permissão pra usar esse comando. Configure `DISCORD_ALLOWED_ROLE_ID` ou `DISCORD_ALLOWED_USER_IDS` (veja backend/DISCORD_BOT.md), ou peça pro administrador do servidor.',
            ephemeral: true,
        });
        return true;
    }

    client.on('interactionCreate', async (interaction) => {
        if (!interaction.isChatInputCommand()) {
            return;
        }

        try {
            if (interaction.commandName === 'gerarkey') {
                if (await denyIfNotAuthorized(interaction)) return;
                await handleGerarKey(interaction);
            } else if (interaction.commandName === 'revogarkey') {
                if (await denyIfNotAuthorized(interaction)) return;
                await handleRevogarKey(interaction);
            } else if (interaction.commandName === 'estoque') {
                if (await denyIfNotAuthorized(interaction)) return;
                await handleEstoque(interaction);
            } else if (interaction.commandName === 'verkey') {
                if (await denyIfNotAuthorized(interaction)) return;
                await handleVerKey(interaction);
            } else if (interaction.commandName === 'loja') {
                await handleLoja(interaction); // público, sem checar permissão
            }
        } catch (e) {
            console.error(`[discord-bot] Erro no comando ${interaction.commandName}:`, e);
            const payload = { content: '❌ Deu erro ao processar. Confere os logs do servidor.', ephemeral: true };
            if (interaction.deferred || interaction.replied) {
                await interaction.editReply(payload).catch(() => {});
            } else {
                await interaction.reply(payload).catch(() => {});
            }
        }
    });

    async function handleGerarKey(interaction) {
        await interaction.deferReply(); // visível no canal e fica salvo no histórico

        const nota = interaction.options.getString('nota') || `Discord: ${interaction.user.tag}`;
        const ativacoes = interaction.options.getInteger('ativacoes') || 1;
        const dias = interaction.options.getInteger('dias') || null;
        const comprador = interaction.options.getUser('comprador');

        const license = await createLicense({
            tier: 'pro',
            note: nota,
            maxActivations: ativacoes,
            expiresInDays: dias,
            buyerDiscordId: comprador ? comprador.id : null,
        });

        const embed = new EmbedBuilder()
            .setColor(0x2ecc71)
            .setTitle('✅ Key gerada')
            .addFields(
                { name: 'Key', value: `\`${license.key}\`` },
                { name: 'Ativações', value: String(ativacoes), inline: true },
                { name: 'Validade', value: dias ? `${dias} dia(s)` : 'Vitalícia', inline: true },
                { name: 'Nota', value: nota },
            )
            .setFooter({ text: 'Comando no jogo: /realityfps license SUACHAVE' });

        await interaction.editReply({ embeds: [embed] });

        if (comprador) {
            try {
                await comprador.send({
                    content:
                        `🎉 Sua key Pro do **RealityFPS** chegou!\n\n` +
                        `\`${license.key}\`\n\n` +
                        `No jogo, digite:\n\`/realityfps license ${license.key}\`` +
                        (dias
                            ? `\n\nVálida por ${dias} dia(s) a partir de agora. Eu aviso por aqui uns dias antes de vencer.`
                            : '\n\nVitalícia.'),
                });
                await interaction.followUp({ content: `📨 Também mandei a key por DM pra ${comprador}.`, ephemeral: true });
            } catch (dmError) {
                await interaction.followUp({
                    content: `⚠️ Não consegui mandar DM pra ${comprador} (provavelmente DMs fechadas). Copia a key acima e manda manualmente.`,
                    ephemeral: true,
                });
            }
        }

        // Log de vendas num canal, se configurado
        if (salesLogChannelId) {
            try {
                const channel = await client.channels.fetch(salesLogChannelId);
                await channel.send({
                    content:
                        `🔑 **Nova key gerada** por ${interaction.user} \`${license.key}\` ` +
                        `${comprador ? 'pra ' + comprador : ''} — ${ativacoes} ativação(ões), ` +
                        `${dias ? dias + ' dia(s)' : 'vitalícia'}. Nota: ${nota}`,
                });
            } catch (e) {
                console.error('[discord-bot] Não consegui mandar no canal de log de vendas:', e.message);
            }
        }
    }

    async function handleRevogarKey(interaction) {
        await interaction.deferReply({ ephemeral: true });
        const key = interaction.options.getString('key').trim().toUpperCase();

        const lic = await storeGet(key);
        if (!lic) {
            await interaction.editReply(`❌ Key \`${key}\` não encontrada.`);
            return;
        }
        lic.revoked = true;
        await storeSet(key, lic);
        await interaction.editReply(`✅ Key \`${key}\` revogada. Ela não valida mais no jogo.`);

        if (salesLogChannelId) {
            try {
                const channel = await client.channels.fetch(salesLogChannelId);
                await channel.send(`🚫 Key \`${key}\` revogada por ${interaction.user}.`);
            } catch (e) {
                console.error('[discord-bot] Não consegui mandar no canal de log de vendas:', e.message);
            }
        }
    }

    async function handleEstoque(interaction) {
        await interaction.deferReply({ ephemeral: true });
        const stats = await getLicenseStats();
        const embed = new EmbedBuilder()
            .setColor(0x3498db)
            .setTitle('📦 Estoque - RealityFPS Pro')
            .addFields(
                { name: 'Total de keys geradas', value: String(stats.total), inline: true },
                { name: 'Ativas', value: String(stats.active), inline: true },
                { name: 'Expiradas', value: String(stats.expired), inline: true },
                { name: 'Revogadas', value: String(stats.revoked), inline: true },
                { name: 'Ativações usadas', value: `${stats.activationsUsed} / ${stats.activationsTotal}`, inline: true },
            );
        await interaction.editReply({ embeds: [embed] });
    }

    /**
     * Resolve um UUID de conta Minecraft pro nick atual, usando a API pública da Mojang.
     * Retorna null se não conseguir (conta não-premium/offline, UUID inválido, API fora do
     * ar, etc.) - nesses casos o comando mostra só o UUID mesmo, sem quebrar.
     */
    async function resolveMojangUsername(uuid) {
        try {
            const clean = uuid.replace(/-/g, '');
            const resp = await fetch(`https://sessionserver.mojang.com/session/minecraft/profile/${clean}`);
            if (!resp.ok) {
                return null;
            }
            const data = await resp.json();
            return data && data.name ? data.name : null;
        } catch (e) {
            return null;
        }
    }

    async function handleVerKey(interaction) {
        await interaction.deferReply({ ephemeral: true });
        const key = interaction.options.getString('key').trim().toUpperCase();

        const lic = await storeGet(key);
        if (!lic) {
            await interaction.editReply(`❌ Key \`${key}\` não encontrada.`);
            return;
        }

        // Resolve o nick de cada conta que já ativou essa key. Faz em paralelo (Promise.all)
        // pra não esperar uma chamada de cada vez - a API da Mojang é externa, então pode
        // demorar um pouco dependendo de quantas contas ativaram.
        const uuids = lic.activatedUuids || [];
        const nomes = await Promise.all(uuids.map((u) => resolveMojangUsername(u)));
        const contasTexto = uuids.length === 0
            ? 'Nenhuma conta ativou ainda'
            : uuids.map((u, i) => `• **${nomes[i] || '(nick não encontrado)'}** — \`${u}\``).join('\n');

        const embed = new EmbedBuilder()
            .setColor(lic.revoked ? 0xe74c3c : 0x3498db)
            .setTitle(`🔑 Key ${key}`)
            .addFields(
                { name: 'Status', value: lic.revoked ? '🚫 Revogada' : (lic.expiresAt && Date.now() > lic.expiresAt ? '⌛ Expirada' : '✅ Ativa'), inline: true },
                { name: 'Tier', value: lic.tier || 'pro', inline: true },
                { name: 'Ativações', value: `${uuids.length} / ${lic.maxActivations}`, inline: true },
                { name: 'Validade', value: lic.expiresAt ? new Date(lic.expiresAt).toLocaleString('pt-BR') : 'Vitalícia', inline: true },
                { name: 'Nota', value: lic.note || '—' },
                { name: 'Contas que usaram', value: contasTexto },
            );
        await interaction.editReply({ embeds: [embed] });
    }

    async function handleLoja(interaction) {
        const items = loadShopItems();
        const embed = new EmbedBuilder()
            .setColor(0xffaa00)
            .setTitle('🛒 RealityFPS Pro - Loja')
            .setDescription('Otimização automática de FPS pro Minecraft. Escolha um plano abaixo e chama a staff pra comprar:');

        if (items.length === 0) {
            embed.addFields({ name: 'Catálogo não configurado', value: 'Peça pro admin configurar `SHOP_ITEMS` no backend.' });
        } else {
            for (const item of items) {
                embed.addFields({ name: `${item.name} — ${item.price}`, value: item.desc || '\u200b' });
            }
        }

        await interaction.reply({ embeds: [embed] }); // público, todo mundo no canal vê
    }

    client.login(token).catch((e) => {
        console.error('[discord-bot] Falha ao logar - confere se DISCORD_TOKEN está certo:', e.message);
    });
}

/** Roda periodicamente: avisa por DM quem tem key perto de vencer (só quem foi gerada via /gerarkey com `comprador`). */
async function checkExpiringLicenses(client, { getExpiringLicenses, markExpiryNotified, expiryReminderDays }) {
    try {
        const expiring = await getExpiringLicenses(expiryReminderDays);
        for (const lic of expiring) {
            try {
                const user = await client.users.fetch(lic.buyerDiscordId);
                const daysLeft = Math.max(1, Math.ceil((lic.expiresAt - Date.now()) / (24 * 60 * 60 * 1000)));
                await user.send(
                    `⏰ Sua key Pro do **RealityFPS** (\`${lic.key}\`) vence em ~${daysLeft} dia(s). ` +
                    `Se quiser renovar, chama a gente aqui no Discord!`
                );
                console.log(`[discord-bot] Lembrete de expiração enviado pra ${lic.buyerDiscordId} (key ${lic.key}).`);
            } catch (e) {
                console.error(`[discord-bot] Não consegui avisar ${lic.buyerDiscordId} sobre a key ${lic.key}:`, e.message);
            }
            await markExpiryNotified(lic.key);
        }
    } catch (e) {
        console.error('[discord-bot] Erro ao checar licenças expirando:', e);
    }
}

module.exports = { initDiscordBot };
