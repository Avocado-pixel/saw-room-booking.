<?php
/**
 * Página "As minhas reservas" para utilizadores autenticados.
 *
 * Funções principais desta página:
 *   - listar as reservas do utilizador com paginação e pesquisa pelo nome da sala;
 *   - permitir cancelar reservas futuras de forma segura;
 *   - permitir editar data/hora/duração de reservas futuras reutilizando a mesma
 *     lógica de validação usada ao criar reservas (ReservationHelper);
 *   - registar todas as alterações em ficheiros de log através da classe Logger,
 *     permitindo auditoria posterior (quem alterou, quando e para que datas).
 *
 * Medidas de segurança importantes:
 *   - verificação de sessão (apenas utilizadores autenticados acedem);
 *   - token CSRF obrigatório em todos os formulários POST (cancelar/editar);
 *   - limpeza de dados recebidos com Security::clean_array;
 *   - verificação de que a reserva pertence ao utilizador e é futura antes de
 *     permitir cancelar ou editar;
 *   - validação de datas, horas, duração e conflitos de horários através de
 *     ReservationHelper::validateInterval.
 */

// Garante que a sessão está iniciada
if(!isset($_SESSION)) session_start();
// Se não houver utilizador autenticado, redireciona para a página de login
if(empty($_SESSION['user_id'])) { header('Location: /index.php?page=login'); exit; }

// Carrega o bootstrap (PDO, logger, etc.), o layout de cliente e helpers de segurança
if(!isset($pdo)) require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../core/ClientLayout.php';
require_once __DIR__ . '/../core/security.php';

// ReservationHelper (em core/ReservationHelper.php) centraliza validação de datas
// e verificação de conflitos de reservas. O autoloader do bootstrap carrega-o
// automaticamente quando a classe é usada.


// ID do utilizador atual (vem da sessão após login bem sucedido)
$userId = (int)$_SESSION['user_id'];


// Handler simples para ações POST: cancelar ou editar reserva (sem AJAX para manter simples).
// Nota: usamos o campo "res_action" para não colidir com o router global index.php?action=...
if($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['res_action'])){
	$post = \Security::clean_array($_POST);
	if(!\Security::verify_csrf($post['csrf'] ?? '')){
		$_SESSION['flash_error'] = 'Sessão inválida. Tente novamente.';
		header('Location: /index.php?page=user_reservas'); exit;
	}

	$action = $post['res_action'];

	if($action === 'cancelar'){
		$resId = (int)($post['reserva_id'] ?? 0);
		if($resId > 0){
			// buscar dados previamente (só reservas futuras do próprio utilizador)
			$stSel = $pdo->prepare("SELECT id,sala_id,data_inicio,data_fim FROM reservas WHERE id = :id AND user_id = :uid AND data_inicio > NOW() LIMIT 1");
			$stSel->execute([':id'=>$resId, ':uid'=>$userId]);
			$row = $stSel->fetch(PDO::FETCH_ASSOC);
			if($row){
				$stDel = $pdo->prepare("DELETE FROM reservas WHERE id = :id AND user_id = :uid");
				$stDel->execute([':id'=>$resId, ':uid'=>$userId]);
				if(isset($logger) && method_exists($logger,'audit_reserva')){
					$details = "Reserva {$resId} sala {$row['sala_id']} apagada (de {$row['data_inicio']} a {$row['data_fim']})";
					$logger->audit_reserva($userId,'RESERVA_CANCELADA',$details);
				}
				$_SESSION['flash_success'] = 'Reserva cancelada.';
			} else {
				$_SESSION['flash_error'] = 'Não foi possível cancelar a reserva (pode já ter ocorrido ou não pertencer a si).';
			}
		}
		header('Location: /index.php?page=user_reservas'); exit;
	}

	if($action === 'editar'){
		$resId = (int)($post['reserva_id'] ?? 0);
		$data = trim($post['data'] ?? '');
		$hora = trim($post['hora'] ?? '');
		$dur  = (int)($post['duracao'] ?? 0);

		if($resId <= 0){
			$_SESSION['flash_error'] = 'Reserva inválida.';
			header('Location: /index.php?page=user_reservas'); exit;
		}

		// carregar reserva para verificar pertença e sala e que é futura
		$stR = $pdo->prepare("SELECT id,user_id,sala_id,data_inicio FROM reservas WHERE id = :id AND user_id = :uid LIMIT 1");
		$stR->execute([':id'=>$resId, ':uid'=>$userId]);
		$res = $stR->fetch(PDO::FETCH_ASSOC);
		if(!$res){
			$_SESSION['flash_error'] = 'Reserva não encontrada.';
			header('Location: /index.php?page=user_reservas'); exit;
		}
		// só permitir editar reservas futuras
		if(strtotime($res['data_inicio']) <= time()){
			$_SESSION['flash_error'] = 'Só é possível editar reservas futuras.';
			header('Location: /index.php?page=user_reservas'); exit;
		}

		// usar helper para validar e verificar conflitos (exclui a própria reserva ao verificar)
		$val = ReservationHelper::validateInterval($pdo, $data, $hora, $dur, (int)$res['sala_id'], $resId);
		if(!$val['ok']){
			$_SESSION['flash_error'] = $val['error'];
			header('Location: /index.php?page=user_reservas&edit_id='.$resId); exit;
		}

		// actualizar
		$upd = $pdo->prepare("UPDATE reservas SET data_inicio = :di, data_fim = :df WHERE id = :id AND user_id = :uid");
		$upd->execute([':di'=>$val['inicioSql'], ':df'=>$val['fimSql'], ':id'=>$resId, ':uid'=>$userId]);

		if(isset($logger) && method_exists($logger,'audit_reserva')){
			$details = "Reserva {$resId} sala {$res['sala_id']} atualizada para {$val['inicioSql']} a {$val['fimSql']}";
			$logger->audit_reserva($userId,'RESERVA_EDITADA',$details);
		}

		$_SESSION['flash_success'] = 'Reserva actualizada com sucesso.';
		header('Location: /index.php?page=user_reservas'); exit;
	}
}

// PAGINAÇÃO + PESQUISA das reservas deste utilizador
$params = [':uid' => $userId];
$sqlBase = "
	FROM reservas r
	JOIN salas s ON s.id = r.sala_id
	WHERE r.user_id = :uid
";

// Paginator: 5 reservas por página
$p = new Paginator($_GET, 5);
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
	       r.token_partilha,
	       r.sala_id,
	       s.nome AS sala_nome
	".$sqlBase."
	ORDER BY r.data_inicio DESC
	".$p->limitSql();
$st = $pdo->prepare($sqlList);
$st->execute($params);
$reservas = $st->fetchAll(PDO::FETCH_ASSOC);

$editId = (int)($_GET['edit_id'] ?? 0);

// flash
$flashErr = $_SESSION['flash_error'] ?? null; if($flashErr) unset($_SESSION['flash_error']);
$flashOk  = $_SESSION['flash_success'] ?? null; if($flashOk) unset($_SESSION['flash_success']);

render_client_page('As minhas reservas', function() use ($reservas, $flashErr, $flashOk, $p, $editId){
	$agora = new DateTime('now');
	?>
	<h1 style="margin:0 0 12px 0;font-size:1.7rem;">As minhas reservas</h1>
	<p style="margin:0 0 18px 0;font-size:0.95rem;color:#6b7280;">
	  Veja as suas reservas. Só pode cancelar reservas de datas futuras.
	</p>

	<?php if($flashErr): ?>
	  <div style="margin-bottom:14px;padding:10px 12px;border-radius:8px;background:#fef2f2;color:#b91c1c;font-size:0.9rem;">
	    <?php echo htmlspecialchars($flashErr); ?>
	  </div>
	<?php endif; ?>
	<?php if($flashOk): ?>
	  <div style="margin-bottom:14px;padding:10px 12px;border-radius:8px;background:#ecfdf3;color:#166534;font-size:0.9rem;">
	    <?php echo htmlspecialchars($flashOk); ?>
	  </div>
	<?php endif; ?>

	<!-- Barra de pesquisa por nome de sala -->
	<?php echo $p->renderSearchForm('Procurar por sala...', 'q'); ?>

	<?php if(empty($reservas)): ?>
	  <p style="font-size:0.95rem;color:#6b7280;">Ainda não tem reservas.</p>
	<?php else: ?>
	  <div class="client-card" style="padding:4px 0 10px 0; box-shadow: var(--client-shadow-md);">
	    <table style="width:100%;border-collapse:collapse;font-size:0.9rem;">
	      <thead>
	        <tr style="background:#f1f5f9;">
	          <th style="padding:10px 14px;text-align:left;">Sala</th>
	          <th style="padding:10px 14px;text-align:left;">Início</th>
	          <th style="padding:10px 14px;text-align:left;">Fim</th>
	          <th style="padding:10px 14px;text-align:left;">Duração</th>
	          <th style="padding:10px 14px;text-align:left;">Ações</th>
	        </tr>
	      </thead>
	      <tbody>
	        <?php foreach($reservas as $r): ?>
	          <?php
	            $inicio = new DateTime($r['data_inicio']);
	            $fim    = new DateTime($r['data_fim']);
	            $eFuturo = ($inicio > $agora);

	            $diff = $inicio->diff($fim);
	            $mins = $diff->days*24*60 + $diff->h*60 + $diff->i;
	            $durLabel = $mins >= 60
	              ? floor($mins/60).'h'.($mins%60 ? ' '.($mins%60).'m' : '')
	              : $mins.' min';
	          ?>
	          <tr style="border-top:1px solid #e5e7eb;">
	            <td style="padding:9px 14px;font-weight:600;"><?php echo htmlspecialchars($r['sala_nome']); ?></td>
	            <td style="padding:9px 14px;"><?php echo htmlspecialchars($r['data_inicio']); ?></td>
	            <td style="padding:9px 14px;"><?php echo htmlspecialchars($r['data_fim']); ?></td>
	            <td style="padding:9px 14px;font-weight:600;"><?php echo htmlspecialchars($durLabel); ?></td>
			            <td style="padding:9px 14px;">
							<?php if($eFuturo): ?>
								<a href="/index.php?page=user_reservas&edit_id=<?php echo (int)$r['id']; ?>" class="client-btn" style="margin-right:6px;padding:4px 10px;font-size:0.8rem;background:#0ea5ad;color:#fff;text-decoration:none;">Editar</a>
								<form method="post" action="/index.php?page=user_reservas" style="display:inline;">
									<input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
			                  <input type="hidden" name="res_action" value="cancelar">
									<input type="hidden" name="reserva_id" value="<?php echo (int)$r['id']; ?>">
									<button type="submit" class="client-btn"
													style="background:#ef4444;color:#fff;padding:4px 10px;font-size:0.8rem;"
													onclick="return confirm('Cancelar esta reserva?');">
										Cancelar
									</button>
								</form>
							<?php else: ?>
								<span style="color:#6b7280;font-size:0.8rem;">Concluída</span>
							<?php endif; ?>
						</td>
					</tr>
					<?php if($editId && $editId == $r['id'] && $eFuturo): ?>
						<tr style="background:#f8fafc;">
							<td colspan="5" style="padding:12px 14px;">
								<?php
									$dateVal = $inicio->format('Y-m-d');
									$horaVal = $inicio->format('H:i');
									$durMins = (int)(($fim->getTimestamp() - $inicio->getTimestamp()) / 60);
								?>
								<form method="post" action="/index.php?page=user_reservas" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
					                  <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
					                  <input type="hidden" name="res_action" value="editar">
									<input type="hidden" name="reserva_id" value="<?php echo (int)$r['id']; ?>">

									<label style="font-size:0.9rem;">Data</label>
									<input type="date" name="data" value="<?php echo htmlspecialchars($dateVal); ?>" required>

									<label style="font-size:0.9rem;">Hora</label>
									<select name="hora" required>
										<?php
										for($h=8; $h<=20; $h++){
											foreach([0,30] as $m){
												$label = sprintf('%02d:%02d', $h, $m);
												$sel = ($label === $horaVal) ? ' selected' : '';
												echo '<option value="'.$label.'"'.$sel.'>'.$label.'</option>';
											}
										}
										?>
									</select>

									<label style="font-size:0.9rem;">Duração</label>
									<select name="duracao" required>
										<?php
											$opts = [30,60,90,120];
											foreach($opts as $o){
												$s = ($o === $durMins) ? ' selected' : '';
												echo '<option value="'.$o.'"'.$s.'>'.$o.' minutos'.($o>=60 ? ' ('.(int)($o/60).'h)':'' ).'</option>';
											}
										?>
									</select>

									<div style="margin-left:auto;">
										<button type="submit" class="client-btn primary">Salvar alterações</button>
										<a href="/index.php?page=user_reservas" class="client-btn" style="background:#e5e7eb;color:#111827;margin-left:8px;text-decoration:none;padding:6px 10px;border-radius:6px;">Cancelar</a>
									</div>
								</form>
							</td>
			            </tr>
			          <?php endif; ?>
	        <?php endforeach; ?>
	      </tbody>
	    </table>
	  </div>

	  <!-- Paginação -->
	  <?php echo $p->renderLinks('p'); ?>
	<?php endif; ?>
	<?php
});
