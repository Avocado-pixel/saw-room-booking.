SAW Room Booking Aplicação web em PHP para gestão de reservas de salas (salas de reunião, espaços de trabalho, laboratórios, etc.), com áreas distintas para utilizadores finais e administradores. O sistema permite gerir salas, horários e reservas de forma centralizada, com autenticação, recuperação de password e funcionalidades de auditoria.

Funcionalidades principais Gestão de utilizadores

Registo de novos utilizadores com validação de email. Login, logout e “remember me”. Perfil de utilizador com possibilidade de atualizar dados e foto. Recuperação de password via email (pedir reset / definir nova password). Suporte para 2FA (Two-Factor Authentication) através de códigos temporários (TOTP). Gestão de salas

Criação, edição e remoção de salas (admin). Atribuição de atributos às salas (nome, capacidade, descrição, imagem, etc.). Listagem pública de salas disponíveis. Reservas

Utilizadores autenticados podem reservar salas disponíveis. Consulta do histórico de reservas do próprio utilizador. Área de administração para visualizar e gerir todas as reservas.

Área de administração

Dashboard para visão global do sistema. Gestão de utilizadores (ativar/desativar, alterar perfil/role). Gestão de salas (CRUD completo). Gestão e auditoria de reservas. Registo de ações importantes em ficheiros de log. Segurança e auditoria

Sistema de autenticação centralizado com controlo de sessão e expiração por inatividade. Proteção de rotas: páginas de utilizador e admin só são acessíveis com as permissões certas. Logs de erros e de ações críticas (como acessos proibidos, alterações de dados, etc.). Diretório privado para uploads de perfis e outros ficheiros sensíveis, não acessível diretamente via web. Integração com 2FA via biblioteca externa.

Tecnologias utilizadas Backend:

PHP 8+ PDO para acesso à base de dados (MySQL/MariaDB ou compatível) PHPMailer para envio de emails (reset de password, validação de conta) Biblioteca de 2FA (RobThree/TwoFactorAuth) Composer para gestão de dependências Frontend:

HTML5, CSS3 JavaScript (validações no lado do cliente, gestão de sessão via AJAX em alguns pontos) Layouts separados para área pública, área do cliente e área de administração Servidor:

Apache 2.4 (com .htaccess para reescrita de URLs) Suporte a HTTPS recomendado

Estrutura geral public_html/ como raiz da aplicação: index.php como ponto de entrada e router principal. Diretórios public, cliente e administracao com as páginas para: visitantes anónimos (páginas públicas), utilizadores autenticados, administradores. core com classes de apoio (autenticação, layouts, logger, helpers, validações). config com configuração de base de dados e email. assets com CSS e JS. private para uploads e logs, fora do alcance direto do público. vendor com dependências do Composer.

Fluxo de navegação Visitantes:

Entram pela página pública de listagem de salas. Podem registar-se, iniciar sessão e recuperar password. Utilizadores autenticados:

Acedem à área de cliente para: reservar salas, consultar reservas, gerir o perfil (dados pessoais e foto). Administradores:

Acedem à área de administração para: gerir utilizadores, gerir salas, gerir reservas, consultar logs/auditorias.

Objetivo do projeto O objetivo deste projeto é fornecer uma solução simples, extensível e segura para gestão de reservas de salas, adequada tanto para contextos académicos (escolas, universidades) como para empresas ou organizações que precisem de coordenar o uso de espaços físicos. O código foi organizado de forma a ser fácil de compreender, adaptar e evoluir.
