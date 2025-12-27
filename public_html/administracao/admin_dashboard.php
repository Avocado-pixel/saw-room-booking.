<?php
/**
 * Dashboard principal da área de administração.
 *
 * Mostra uma visão geral do sistema:
 *   - número total de utilizadores registados;
 *   - número total de salas criadas (incluindo as não disponíveis);
 *   - número total de reservas existentes.
 *
 * A partir daqui o administrador pode navegar rapidamente para a gestão de
 * salas, utilizadores e reservas. O acesso é restrito a utilizadores com
 * perfil 'admin', verificado logo no início do ficheiro.
 */

// Garante sessão ativa e bloqueia utilizadores não administradores
if(!isset($_SESSION)) session_start();
// Bloqueia acesso a utilizadores não autenticados ou sem perfil de administrador
if(empty($_SESSION['user_id']) || ($_SESSION['perfil'] ?? '') !== 'admin'){
	http_response_code(403); echo "Acesso negado."; exit;
}
if(!isset($pdo)) require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../core/AdminLayout.php';

// Contagens rápidas para mostrar estatísticas no topo do painel
$c1 = (int)$pdo->query("SELECT COUNT(*) FROM utilizadores")->fetchColumn();
$c2 = (int)$pdo->query("SELECT COUNT(*) FROM salas")->fetchColumn();
$c3 = (int)$pdo->query("SELECT COUNT(*) FROM reservas")->fetchColumn();

// Usa o layout comum de administração para renderizar a página
render_admin_page('Dashboard', function() use ($c1, $c2, $c3){
	?>
	<div class="admin-dashboard-center">
	  <div class="admin-card">
	    <h1>Painel de administração</h1>

	    <div class="stats-row">
	      <div class="stat">
	        <div class="stat-value"><?php echo $c2; ?></div>
	        <div class="stat-label">Salas</div>
	      </div>
		  <div class="stat">
	        <div class="stat-value"><?php echo $c1; ?></div>
	        <div class="stat-label">Utilizadores</div>
	      </div>
	      <div class="stat">
	        <div class="stat-value"><?php echo $c3; ?></div>
	        <div class="stat-label">Reservas</div>
	      </div>
	    </div>

	    <div class="dashboard-grid">
	      <a class="card" href="/index.php?page=admin_rooms">
	        <div class="card-icon">🏛️</div>
	        <h3>Gerir Salas</h3>
	        <p>Adicionar, editar ou remover salas.</p>
	      </a>
	      <a class="card" href="/index.php?page=admin_users">
	        <div class="card-icon">👥</div>
	        <h3>Utilizadores</h3>
	        <p>Ver e gerir utilizadores registados.</p>
	      </a>
	      <a class="card" href="/index.php?page=admin_reservas">
	        <div class="card-icon">📅</div>
	        <h3>Reservas</h3>
	        <p>Acompanhar e gerir reservas de salas.</p>
	      </a>
	    </div>
	  </div>
	</div>
	<?php
});
