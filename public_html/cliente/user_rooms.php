<?php
/**
 * Lista de salas disponível para o utilizador autenticado.
 *
 * Mostra as salas (não eliminadas) com:
 *   - paginação (6 por página) e pesquisa por nome;
 *   - capacidade e estado operacional (disponível/indisponível/brevemente);
 *   - botão de "Reservar" que encaminha para user_reservar.php com o
 *     sala_id correto.
 *
 * Esta página reutiliza o componente de paginação Paginator e o layout de
 * cliente (ClientLayout).
 */

// Garante sessão e acesso apenas a utilizadores autenticados
if(!isset($_SESSION)) session_start();
if(empty($_SESSION['user_id'])) { header('Location: /index.php?page=login'); exit; }
if(!isset($pdo)) require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../core/ClientLayout.php';

// Paginação + pesquisa de salas para utilizador autenticado
$params = [];
$sqlBase = "FROM salas WHERE estado_registo != 'eliminado'";

$p = new Paginator($_GET, 6); // 6 salas por página
if($p->hasSearch()){
	$sqlBase .= " AND nome LIKE :q";
	$params[':q'] = '%'.$p->getSearch().'%';
}

// contar total
$stCount = $pdo->prepare("SELECT COUNT(*) ".$sqlBase);
$stCount->execute($params);
$p->setTotal((int)$stCount->fetchColumn());

// buscar salas desta página (inclui estado para mostrar disponibilidade)
$sqlList = "SELECT id,nome,capacidade,estado,foto ".$sqlBase." ORDER BY nome ".$p->limitSql();
$st = $pdo->prepare($sqlList);
$st->execute($params);
$salas = $st->fetchAll(PDO::FETCH_ASSOC);

// render layout cliente
render_client_page('Salas', function() use ($salas, $p){
	?>
	<h1 style="margin:0 0 12px 0;font-size:1.7rem;">Salas</h1>
	<p style="margin:0 0 18px 0;font-size:0.95rem;color:#6b7280;">
	  Veja as salas disponíveis para reserva.
	</p>

	<?php echo $p->renderSearchForm('Procurar sala...', 'q'); ?>

	<?php if(empty($salas)): ?>
	  <p style="font-size:0.95rem;color:#6b7280;">Nenhuma sala encontrada.</p>
	<?php else: ?>
	  <div style="display:grid;grid-template-columns:repeat(3, minmax(0, 1fr));gap:14px;align-items:stretch;">
	    <?php foreach($salas as $s): ?>
	      <?php
	        	$foto   = !empty($s['foto']) ? '/room_image.php?file='.rawurlencode($s['foto']) : null;
	        $estado = $s['estado'] ?? 'disponivel';
	        $estadoLabel = ucfirst($estado);
	        $badgeColor = '#0f5132';
	        if($estado === 'indisponivel') $badgeColor = '#b91c1c';
	        if($estado === 'brevemente')   $badgeColor = '#92400e';
	        $roomId = (int)$s['id'];
	      ?>
	      <article class="client-card" style="display:flex;flex-direction:column;overflow:hidden;min-height:260px;padding:0;">
	        <?php if($foto): ?>
	          <div style="height:120px;background:#e5e7eb;overflow:hidden;">
	            <img src="<?php echo $foto; ?>" alt="Foto da sala"
	                 style="width:100%;height:100%;object-fit:cover;">
	          </div>
	        <?php endif; ?>

	        <div style="padding:10px 12px;display:flex;flex-direction:column;gap:6px;flex:1;">
	          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
	            <h2 style="margin:0;font-size:1.02rem;"><?php echo htmlspecialchars($s['nome']); ?></h2>
	            <span style="padding:2px 8px;border-radius:999px;font-size:0.78rem;color:#fff;background:<?php echo $badgeColor; ?>;">
	              <?php echo htmlspecialchars($estadoLabel); ?>
	            </span>
	          </div>
	          <div style="font-size:0.9rem;color:#6b7280;">
	            Capacidade: <strong><?php echo (int)$s['capacidade']; ?></strong> pessoas
	          </div>

	          <div style="margin-top:auto;">
	            <?php if($estado === 'disponivel'): ?>
	              <a href="/index.php?page=user_reservar&sala_id=<?php echo $roomId; ?>"
	                 style="display:inline-block;padding:6px 12px;border-radius:8px;background:#0057b7;
	                        color:#fff;text-decoration:none;font-weight:600;font-size:0.9rem;">
	                Reservar
	              </a>
	            <?php else: ?>
	              <!-- sem botão quando não está disponível -->
	            <?php endif; ?>
	          </div>
	        </div>
	      </article>
	    <?php endforeach; ?>
	  </div>

	  <?php echo $p->renderLinks('p'); ?>
	<?php endif; ?>
	<?php
});
