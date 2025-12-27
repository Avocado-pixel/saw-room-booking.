<?php
/**
 * Página de reservas (vista de administração).
 *
 * Aqui o administrador consegue:
 *   - escolher um dia específico de calendário;
 *   - ver todas as reservas de todas as salas nesse dia;
 *   - pesquisar pelo nome da sala;
 *   - navegar por páginas de resultados (5 reservas por página).
 *
 * Esta vista serve principalmente para monitorizar a ocupação das salas e
 * apoiar a gestão diária.
 *
 * Segurança:
 *   - apenas utilizadores com perfil 'admin' têm acesso;
 *   - o acesso é protegido pelo router principal (index.php?page=admin_reservas)
 *     e por esta verificação local;
 *   - cada consulta a um dia é registada no log através de
 *     Logger::audit_admin_reservas, de forma a saber que administrador
 *     consultou que dia e quando.
 */

// Verifica sessão e perfil de administrador
if(!isset($_SESSION)) session_start();
if(empty($_SESSION['user_id']) || ($_SESSION['perfil'] ?? '') !== 'admin'){
	http_response_code(403);
	echo "Acesso negado.";
	exit;
}
if(!isset($pdo)) require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../core/AdminLayout.php';

// ler data escolhida (GET)
$data = trim($_GET['data'] ?? '');
$hasDate = (bool)preg_match('/^\d{4}-\d{2}-\d{2}$/', $data);

$reservas = [];
$p = null;

if($hasDate){
	// intervalo [data 00:00, data+1 00:00)
	$inicioDia = $data . ' 00:00:00';
	$fimDia    = date('Y-m-d 00:00:00', strtotime($data . ' +1 day'));

	$params = [
		':di' => $inicioDia,
		':df' => $fimDia,
	];

	$sqlBase = "
		FROM reservas r
		JOIN salas s ON s.id = r.sala_id
		JOIN utilizadores u ON u.id = r.user_id
		WHERE r.data_inicio >= :di
		  AND r.data_inicio < :df
	";

	// paginação + pesquisa por nome da sala
	$p = new Paginator($_GET, 5); // 5 reservas por página
	if($p->hasSearch()){
		$sqlBase .= " AND s.nome LIKE :q";
		$params[':q'] = '%'.$p->getSearch().'%';
	}

	// contar total
	$stCount = $pdo->prepare("SELECT COUNT(*) ".$sqlBase);
	$stCount->execute($params);
	$p->setTotal((int)$stCount->fetchColumn());

	// carregar reservas desta página
	$sqlList = "
		SELECT r.id,
		       r.data_inicio,
		       r.data_fim,
		       s.nome AS sala_nome,
		       u.nome AS user_nome,
		       u.email AS user_email
		".$sqlBase."
		ORDER BY r.data_inicio
		".$p->limitSql();
	$st = $pdo->prepare($sqlList);
	$st->execute($params);
	$reservas = $st->fetchAll(PDO::FETCH_ASSOC);

	// auditoria: admin consultou reservas de um dia específico
	if(isset($logger) && method_exists($logger,'audit_admin_reservas')){
		$adminId = $_SESSION['user_id'] ?? null;
		$logger->audit_admin_reservas($adminId,'VIEW_DAILY_RESERVAS',"Admin {$adminId} consultou reservas do dia {$data}");
	}
}

render_admin_page('Reservas', function() use ($data, $hasDate, $reservas, $p){
	?>
	<h2>Reservas por dia</h2>
	<p class="text-muted" style="margin-bottom:12px;font-size:0.9rem;">
	  Escolha um dia para ver a ocupação das salas. Pode também pesquisar pelo nome da sala.
	</p>

	<form method="get" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px;">
	  <input type="hidden" name="page" value="admin_reservas">
	  <label style="font-size:0.9rem;color:#4b5563;">
	    Dia:
	    <input type="date" name="data" value="<?php echo htmlspecialchars($data); ?>"
	           style="margin-left:4px;padding:4px 6px;border-radius:6px;border:1px solid #d1d5db;">
	  </label>
	  <button type="submit" class="btn-admin" style="padding:6px 12px;">Ver reservas</button>
	</form>

	<?php if($hasDate && $p): ?>
	  <!-- barra de pesquisa por sala (usa Paginator) -->
	  <?php echo $p->renderSearchForm('Procurar por sala...', 'q'); ?>
	<?php endif; ?>

	<?php if(!$hasDate): ?>
	  <p class="text-muted" style="font-size:0.9rem;margin-top:10px;">
	    Selecione um dia acima e clique em "Ver reservas" para carregar os resultados.
	  </p>
	<?php else: ?>

	  <?php if(empty($reservas)): ?>
	    <div class="admin-card" style="margin-top:10px;">
	      <p style="margin:0;font-size:0.9rem;color:#6b7280;">
	        Não existem reservas para este dia (ou para o filtro aplicado).
	      </p>
	    </div>
	  <?php else: ?>
	    <div class="admin-card" style="margin-top:10px;padding:0;">
	      <table class="table" style="margin:0;border-radius:10px 10px 0 0;box-shadow:none;">
	        <thead>
	          <tr>
	            <th>Sala</th>
	            <th>Utilizador</th>
	            <th>Email</th>
	            <th>Início</th>
	            <th>Fim</th>
	          </tr>
	        </thead>
	        <tbody>
	          <?php foreach($reservas as $r): ?>
	            <tr>
	              <td><?php echo htmlspecialchars($r['sala_nome']); ?></td>
	              <td><?php echo htmlspecialchars($r['user_nome']); ?></td>
	              <td><?php echo htmlspecialchars($r['user_email']); ?></td>
	              <td><?php echo htmlspecialchars($r['data_inicio']); ?></td>
	              <td><?php echo htmlspecialchars($r['data_fim']); ?></td>
	            </tr>
	          <?php endforeach; ?>
	        </tbody>
	      </table>
	    </div>

	    <!-- paginação -->
	    <?php echo $p->renderLinks('p'); ?>
	  <?php endif; ?>

	<?php endif; ?>
	<?php
});
