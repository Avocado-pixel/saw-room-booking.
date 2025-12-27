<?php
/**
 * Layout comum para a área de administração.
 *
 * Responsabilidades principais:
 * - Gera o HTML base da área de admin (head, topbar, estrutura do body).
 * - Inclui os CSS específicos de administração.
 * - Recebe um título e um callback que imprime o conteúdo dentro de .admin-wrap.
 *
 * Nota: A verificação de permissões (se é admin ou não) é feita
 * nos ficheiros de página (ex.: admin_dashboard.php) antes de chamar esta função.
 */
function render_admin_page(string $title, callable $contentRenderer): void {
	// Garante que existe sessão para poder usar dados do utilizador, se necessário
	if(!isset($_SESSION)) session_start();

	?>
	<!doctype html>
	<html lang="pt">
	<head>
	  <meta charset="utf-8">
	  <title><?php echo htmlspecialchars($title); ?> — Administração</title>
	  <!-- CSS do admin (fundo + barra + cartões) -->
	  <link rel="stylesheet" href="/assets/css/style_admin.css">
	  <!-- CSS específico de salas (não mexe no body) -->
	  <link rel="stylesheet" href="/assets/css/rooms.css">
	</head>
	<body class="admin-area">
	  <!-- Barra superior fixa com navegação da área de administração -->
	  <header class="admin-topbar admin-topbar-fixed" role="navigation" aria-label="Admin">
	    <div class="topbar-left">
	      <a class="admin-logo" href="/index.php?page=admin_dashboard">
	        <span class="mark"></span>
	        <span class="title">SAW — Administração</span>
	      </a>
	    </div>
	    <!-- Navegação principal entre as secções de administração -->
	    <nav class="topbar-nav">
		  <a class="nav-link" href="/index.php?page=admin_dashboard">Painel</a>
	      <a class="nav-link" href="/index.php?page=admin_rooms">Salas</a>
	      <a class="nav-link" href="/index.php?page=admin_users">Utilizadores</a>
	      <a class="nav-link" href="/index.php?page=admin_reservas">Reservas</a>
	    </nav>
	    <!-- Ações rápidas à direita: acesso ao perfil, eliminar conta e logout -->
	    <div class="topbar-actions">
	      <a class="btn-top" href="/index.php?page=user_profile">Perfil</a>
	      <a class="btn-top primary" href="/index.php?action=logout">Logout</a>
	    </div>
	  </header>

	  <!-- Conteúdo específico da página de administração -->
	  <div class="admin-wrap" role="main">
	    <?php $contentRenderer(); ?>
	  </div>
	</body>
	</html>
	<?php
}
