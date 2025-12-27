<?php
/**
 * Layout comum para a área do cliente.
 *
 * Responsabilidades principais:
 * - Montar o HTML base da área de cliente (head, topbar, main).
 * - Incluir o CSS específico do cliente.
 * - Receber um título e um callback que imprime o conteúdo dentro de <main>.
 *
 * Tal como no layout de admin, a proteção de acesso (require_auth)
 * é feita no router/index.php ou nos ficheiros de página antes de chamar esta função.
 */
function render_client_page(string $title, callable $contentRenderer): void {
	// Garante que a sessão está disponível para aceder a dados do utilizador
	if(!isset($_SESSION)) session_start();
	?>
	<!doctype html>
	<html lang="pt">
	<head>
	  <meta charset="utf-8">
	  <title><?php echo htmlspecialchars($title); ?> — SAW</title>
	  <!-- CSS específico da área do cliente (fundo + barra) -->
	  <link rel="stylesheet" href="/assets/css/style_client.css">
	  <!-- CSS público genérico (forms básicos, etc.) -->
	</head>
	<body class="client-area">
	  <!-- Barra superior da área do cliente com logo e navegação -->
	  <header class="client-topbar" role="navigation" aria-label="Navegação cliente">
	    <div class="client-topbar-left">
	      <div class="client-logo-mark"></div>
	      <div class="client-logo-text">SAW — Área do Cliente</div>
	    </div>
	    <!-- Navegação entre as principais secções da área de cliente -->
	    <nav class="client-topbar-nav">
	      <!-- Emojis adicionados para dar identidade a cada secção -->
	      <a class="client-nav-link" href="/index.php?page=user_profile">👤 Perfil</a>
	      <a class="client-nav-link" href="/index.php?page=user_rooms">🏢 Salas</a>
	      <a class="client-nav-link" href="/index.php?page=user_reservas">📅 Reservas</a>
	    </nav>
	    <!-- Ações à direita: eliminar conta e terminar sessão -->
	    <div class="client-topbar-actions">
	      <a class="client-nav-link" href="/index.php?page=user_eliminar">Eliminar conta</a>
	      <a class="client-logout" href="/index.php?action=logout">Sair</a>
	    </div>
	  </header>

	  <!-- Conteúdo principal específico da página do cliente -->
	  <main class="client-wrap" role="main">
	    <?php $contentRenderer(); ?>
	  </main>
	</body>
	</html>
	<?php
}
