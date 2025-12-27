<?php
/**
 * Página de gestão de utilizadores na área de administração.
 *
 * Responsabilidades principais:
 *   - listar todos os utilizadores com paginação e pesquisa (por nome/email);
 *   - mostrar dados básicos (perfil, estado, NIF, telemóvel, foto de perfil);
 *   - permitir bloquear / desbloquear utilizadores via AJAX;
 *   - permitir ao admin ver a lista de reservas de um utilizador específico,
 *     também com paginação (5 por página).
 *
 * Segurança e auditoria:
 *   - apenas administradores autenticados podem aceder;
 *   - todas as ações de alteração de estado (bloquear/desbloquear) validam
 *     token CSRF e são registadas tanto em audit_user (por utilizador afetado)
 *     como em audit_admin_user (para saber que admin executou a ação);
 *   - quando o admin consulta as reservas de um utilizador, essa ação é
 *     registada em audit_admin_user (VIEW_USER_RESERVAS).
 */

// Verifica sessão e garante que o utilizador tem perfil de administrador
if(!isset($_SESSION)) session_start();
if(empty($_SESSION['user_id']) || ($_SESSION['perfil'] ?? '') !== 'admin'){
	http_response_code(403);
	echo "Acesso negado.";
	exit;
}

function csrf_ok($token){
	if(class_exists('Security') && method_exists('Security','verify_csrf')){
		return \Security::verify_csrf($token);
	}
	$stored = $_SESSION['csrf_token'] ?? '';
	if($stored === '' || $token === '') return false;
	if(function_exists('hash_equals')) return hash_equals((string)$stored, (string)$token);
	return (string)$stored === (string)$token;
}

$csrf = \Security::csrf_token();

if(!isset($pdo)) require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../core/AdminLayout.php';

// Handler para mudar o perfil do utilizador (utente <-> admin)
if($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'admin_set_user_perfil'){
	header('Content-Type: application/json; charset=utf-8');
	$token = $_POST['csrf'] ?? '';
	if(!csrf_ok($token)){
		echo json_encode(['ok'=>false,'msg'=>'CSRF inválido']); exit;
	}

	$id = (int)($_POST['id'] ?? 0);
	$perfilNovo = $_POST['perfil'] ?? '';
	$allowedPerfil = ['admin','utente'];
	if($id <= 0 || !in_array($perfilNovo, $allowedPerfil, true)){
		echo json_encode(['ok'=>false,'msg'=>'Dados inválidos']); exit;
	}

	try {
		// Obter perfil atual do utilizador alvo
		$st = $pdo->prepare("SELECT perfil FROM utilizadores WHERE id = :id");
		$st->execute([':id'=>$id]);
		$perfilAtual = $st->fetchColumn();
		if($perfilAtual === false){
			echo json_encode(['ok'=>false,'msg'=>'Utilizador não encontrado']); exit;
		}

		$adminId = (int)($_SESSION['user_id'] ?? 0);

		// Regra 1: um admin não pode alterar o próprio perfil para deixar de ser admin
		if($id === $adminId && $perfilAtual === 'admin' && $perfilNovo !== 'admin'){
			echo json_encode(['ok'=>false,'msg'=>'Não pode alterar o seu próprio perfil de administrador.']); exit;
		}

		// Regra 2: não é permitido remover o último administrador do sistema
		if($perfilAtual === 'admin' && $perfilNovo !== 'admin'){
			$stCount = $pdo->query("SELECT COUNT(*) FROM utilizadores WHERE perfil = 'admin'");
			$totalAdmins = (int)$stCount->fetchColumn();
			if($totalAdmins <= 1){
				echo json_encode(['ok'=>false,'msg'=>'Não é possível remover o último administrador.']); exit;
			}
		}

		// Aplicar alteração de perfil
		$upd = $pdo->prepare("UPDATE utilizadores SET perfil = :p WHERE id = :id");
		$upd->execute([':p'=>$perfilNovo, ':id'=>$id]);

		if(isset($logger) && method_exists($logger,'audit_user')){
			$logger->audit_user($id,'ADMIN_SET_PERFIL','Perfil alterado para '.$perfilNovo);
		}
		if(isset($logger) && method_exists($logger,'audit_admin_user')){
			$logger->audit_admin_user($adminId,'ADMIN_SET_PERFIL',"Admin {$adminId} alterou o perfil do utilizador {$id} para {$perfilNovo}");
		}

		echo json_encode(['ok'=>true,'perfil'=>$perfilNovo]); exit;
	} catch(PDOException $e){
		if(isset($logger)) $logger->error('ADMIN_SET_PERFIL: '.$e->getMessage());
		echo json_encode(['ok'=>false,'msg'=>'Erro no servidor']); exit;
	}
}

// Handler simples para mudar estado do utilizador (bloquear/desbloquear)
if($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'admin_set_user_estado'){
	header('Content-Type: application/json; charset=utf-8');
	// NOVO: validar CSRF como nas outras ações admin
	$token = $_POST['csrf'] ?? '';
	if(!csrf_ok($token)){
		echo json_encode(['ok'=>false,'msg'=>'CSRF inválido']); exit;
	}

	$id = (int)($_POST['id'] ?? 0);
	$estado = $_POST['estado'] ?? '';
	$allowed = ['disponivel','bloqueado'];
	if($id <= 0 || !in_array($estado, $allowed, true)){
		echo json_encode(['ok'=>false,'msg'=>'Dados inválidos']); exit;
	}
	try {
		// Impedir alterar o estado de utilizadores com perfil de administrador
		$stPerfil = $pdo->prepare("SELECT perfil FROM utilizadores WHERE id = :id");
		$stPerfil->execute([':id'=>$id]);
		$perfil = $stPerfil->fetchColumn();
		if($perfil === false){
			echo json_encode(['ok'=>false,'msg'=>'Utilizador não encontrado']); exit;
		}
		if($perfil === 'admin'){
			echo json_encode(['ok'=>false,'msg'=>'Não é possível bloquear/desbloquear contas de administrador']); exit;
		}

		$st = $pdo->prepare("UPDATE utilizadores SET estado = :e WHERE id = :id");
		$st->execute([':e'=>$estado, ':id'=>$id]);
		if(isset($logger) && method_exists($logger,'audit_user')){
			$logger->audit_user($id,'ADMIN_SET_ESTADO','Estado alterado para '.$estado);
		}
		// novo: auditoria específica de ação de admin sobre utilizador
		if(isset($logger) && method_exists($logger,'audit_admin_user')){
			$adminId = $_SESSION['user_id'] ?? null;
			$logger->audit_admin_user($adminId,'ADMIN_SET_ESTADO',"Admin {$adminId} alterou estado do utilizador {$id} para {$estado}");
		}
		echo json_encode(['ok'=>true]); exit;
	} catch(PDOException $e){
		if(isset($logger)) $logger->error('ADMIN_SET_ESTADO: '.$e->getMessage());
		echo json_encode(['ok'=>false,'msg'=>'Erro no servidor']); exit;
	}
}

// -----------------------------
// Listagem de utilizadores com paginação + pesquisa
// -----------------------------
$params = [];
$sqlBase = "FROM utilizadores";

$p = new Paginator($_GET, 5); // 5 utilizadores por página
if($p->hasSearch()){
	// pesquisar por nome ou email
	$sqlBase .= " WHERE nome LIKE :q OR email LIKE :q";
	$params[':q'] = '%'.$p->getSearch().'%';
}

// contar total
$stCount = $pdo->prepare("SELECT COUNT(*) ".$sqlBase);
$stCount->execute($params);
$p->setTotal((int)$stCount->fetchColumn());

// buscar registos desta página
$sqlList = "SELECT id,nome,email,perfil,foto,nif,telemovel,estado ".$sqlBase." ORDER BY nome ".$p->limitSql();
$stmt = $pdo->prepare($sqlList);
$stmt->execute($params);
$users = $stmt->fetchAll();

$viewUserId = (int)($_GET['view'] ?? 0);
$currentAdminId = (int)($_SESSION['user_id'] ?? 0);
$reservas = [];
$resPaginator = null;
if($viewUserId){
	$paramsR = [':u'=>$viewUserId];
	$sqlBaseR = "FROM reservas r JOIN salas s ON s.id = r.sala_id WHERE r.user_id = :u";

	// paginação de reservas do utilizador (5 por página, parâmetros próprios rp/rq)
	$resPaginator = new Paginator($_GET, 5, 'rp', 'rq');
	$stCountR = $pdo->prepare("SELECT COUNT(*) ".$sqlBaseR);
	$stCountR->execute($paramsR);
	$resPaginator->setTotal((int)$stCountR->fetchColumn());

	$sqlListR = "SELECT r.id, r.data_inicio, r.data_fim, r.token_partilha, s.nome as sala_nome ".$sqlBaseR." ORDER BY r.data_inicio DESC ".$resPaginator->limitSql();
	$stR = $pdo->prepare($sqlListR);
	$stR->execute($paramsR);
	$reservas = $stR->fetchAll();

	// auditoria: admin a ver reservas de um utilizador
	if(isset($logger) && method_exists($logger,'audit_admin_user')){
		$adminId = $_SESSION['user_id'] ?? null;
		$logger->audit_admin_user($adminId,'VIEW_USER_RESERVAS',"Admin {$adminId} consultou reservas do utilizador {$viewUserId}");
	}
}

render_admin_page('Utilizadores', function() use ($users, $viewUserId, $reservas, $csrf, $p, $resPaginator, $currentAdminId){
	?>
	<h2>Utilizadores</h2>

	<!-- Barra de pesquisa (por nome/email) -->
	<?php echo $p->renderSearchForm('Procurar utilizador...', 'q'); ?>

	<table class="table">
	  <thead><tr><th>Foto</th><th>Nome</th><th>Email</th><th>NIF</th><th>Telemóvel</th><th>Perfil</th><th>Estado</th><th>Ações</th></tr></thead>
	  <tbody>
	    <?php foreach($users as $u): ?>
	      <tr data-id="<?php echo (int)$u['id']; ?>">
	        <td style="width:110px;">
	          <?php if(!empty($u['foto'])): ?>
	            <img src="/index.php?action=user_photo&uid=<?php echo (int)$u['id']; ?>" alt="foto" style="max-height:60px;border-radius:6px;object-fit:cover;">
	          <?php endif; ?>
	        </td>
	        <td><?php echo htmlspecialchars($u['nome']); ?></td>
	        <td><?php echo htmlspecialchars($u['email']); ?></td>
	        <td><?php echo htmlspecialchars($u['nif'] ?? ''); ?></td>
	        <td><?php echo htmlspecialchars($u['telemovel'] ?? ''); ?></td>
	        <td class="perfil-col"><?php echo htmlspecialchars($u['perfil']); ?></td>
	        <td class="estado-col"><?php echo htmlspecialchars($u['estado'] ?? 'pendente'); ?></td>
	        <td>
	          <a href="/index.php?page=admin_users&view=<?php echo (int)$u['id']; ?>">Ver reservas</a>
	          <?php if(($u['perfil'] ?? '') !== 'admin'): ?>
	          	<?php if(($u['estado'] ?? 'pendente') === 'bloqueado'): ?>
	            	<button type="button" class="btn-admin" data-estado="disponivel">Desbloquear</button>
	          	<?php else: ?>
	            	<button type="button" class="btn-admin danger" data-estado="bloqueado">Bloquear</button>
	          	<?php endif; ?>
	          <?php endif; ?>

	          <?php if((int)$u['id'] !== $currentAdminId): ?>
	          	<?php if(($u['perfil'] ?? '') === 'admin'): ?>
	          		<button type="button" class="btn-admin secondary" data-perfil="utente">Tornar utente</button>
	          	<?php else: ?>
	          		<button type="button" class="btn-admin secondary" data-perfil="admin">Tornar admin</button>
	          	<?php endif; ?>
	          <?php endif; ?>
	        </td>
	      </tr>
	    <?php endforeach; ?>
	  </tbody>
	</table>

	<!-- Links de paginação -->
	<?php echo $p->renderLinks('p'); ?>

	<?php if($viewUserId): ?>
	  <h3>Reservas do utilizador</h3>
	  <?php if(empty($reservas)): ?>
	    <p>Sem reservas.</p>
	  <?php else: ?>
	    <table class="table">
	      <thead><tr><th>Sala</th><th>Início</th><th>Fim</th></tr></thead>
	      <tbody>
	        <?php foreach($reservas as $r): ?>
	          <tr>
	            <td><?php echo htmlspecialchars($r['sala_nome']); ?></td>
	            <td><?php echo htmlspecialchars($r['data_inicio']); ?></td>
	            <td><?php echo htmlspecialchars($r['data_fim']); ?></td>
	          </tr>
	        <?php endforeach; ?>
	      </tbody>
	    </table>
	    <?php if($resPaginator): ?>
	      <?php echo $resPaginator->renderLinks('rp'); ?>
	    <?php endif; ?>
	  <?php endif; ?>
	<?php endif; ?>

	<script>
	// AJAX para bloquear/desbloquear utilizador e alterar perfil
	document.querySelector('.table tbody').addEventListener('click', function(e){
	  var btnEstado = e.target.closest('button[data-estado]');
	  var btnPerfil = e.target.closest('button[data-perfil]');

	  var tr = e.target.closest('tr[data-id]');
	  if(!tr) return;
	  var id = tr.getAttribute('data-id');
	  if(!id) return;

	  // Alterar estado (bloquear/desbloquear)
	  if(btnEstado){
	    var estado = btnEstado.getAttribute('data-estado');
	    if(!estado) return;

	    var fd = new FormData();
	    fd.append('action','admin_set_user_estado');
	    fd.append('id', id);
	    fd.append('estado', estado);
	    fd.append('csrf', '<?php echo htmlspecialchars($csrf, ENT_QUOTES); ?>');

	    fetch('/index.php', { method:'POST', body: fd, credentials:'include' })
	      .then(r=>r.json())
	      .then(function(res){
	        if(!res || !res.ok){
	          alert(res && res.msg ? res.msg : 'Erro ao alterar estado');
	          return;
	        }
	        tr.querySelector('.estado-col').textContent = estado;
	        if(estado === 'bloqueado'){
	          btnEstado.textContent = 'Desbloquear';
	          btnEstado.classList.remove('danger');
	          btnEstado.setAttribute('data-estado','disponivel');
	        } else {
	          btnEstado.textContent = 'Bloquear';
	          btnEstado.classList.add('danger');
	          btnEstado.setAttribute('data-estado','bloqueado');
	        }
	      })
	      .catch(function(){
	        alert('Erro de comunicação.');
	      });
	    return;
	  }

	  // Alterar perfil (utente <-> admin)
	  if(btnPerfil){
	    var novoPerfil = btnPerfil.getAttribute('data-perfil');
	    if(!novoPerfil) return;

	    var fd2 = new FormData();
	    fd2.append('action','admin_set_user_perfil');
	    fd2.append('id', id);
	    fd2.append('perfil', novoPerfil);
	    fd2.append('csrf', '<?php echo htmlspecialchars($csrf, ENT_QUOTES); ?>');

	    fetch('/index.php', { method:'POST', body: fd2, credentials:'include' })
	      .then(r=>r.json())
	      .then(function(res){
	        if(!res || !res.ok){
	          alert(res && res.msg ? res.msg : 'Erro ao alterar perfil');
	          return;
	        }
	        var perfilCol = tr.querySelector('.perfil-col');
	        if(perfilCol && res.perfil){
	          perfilCol.textContent = res.perfil;
	        }
	        if(res.perfil === 'admin'){
	          btnPerfil.textContent = 'Tornar utente';
	          btnPerfil.setAttribute('data-perfil','utente');
	        } else {
	          btnPerfil.textContent = 'Tornar admin';
	          btnPerfil.setAttribute('data-perfil','admin');
	        }
	      })
	      .catch(function(){
	        alert('Erro de comunicação.');
	      });
	  }
	});
	</script>
	<?php
});
