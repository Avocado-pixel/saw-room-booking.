<?php
/**
 * Página de gestão de salas na área de administração.
 *
 * Permite ao administrador:
 *   - listar salas com paginação e pesquisa por nome;
 *   - criar novas salas (com foto opcional);
 *   - editar salas existentes (nome, capacidade, estado, foto);
 *   - marcar salas como eliminadas (remoção lógica, não apaga registos de reservas).
 *
 * As operações de criação/edição/eliminação são feitas por pedidos AJAX (POST)
 * enviados para /index.php com um campo "action" próprio (admin_add_room,
 * admin_edit_room, admin_delete_room). O router do index utiliza o prefixo
 * admin_ para encaminhar estes pedidos para este ficheiro.
 *
 * Segurança:
 *   - só utilizadores autenticados com perfil 'admin' podem aceder;
 *   - cada pedido POST verifica um token CSRF para impedir ataques de request
 *     forjados;
 *   - uploads de imagens são validados quanto à extensão e movidos para uma
 *     pasta privada;
 *   - todas as operações de criação/edição/eliminação são registadas em logs
 *     através de Logger::audit_sala_admin, permitindo saber que administrador
 *     fez o quê e quando.
 */

// Garante sessão ativa e verifica se o utilizador é administrador
if(!isset($_SESSION)) session_start();
if(empty($_SESSION['user_id']) || ($_SESSION['perfil'] ?? '') !== 'admin'){
	http_response_code(403); echo "Acesso negado."; exit;
}
if(!isset($pdo)) require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../core/AdminLayout.php';

// CSRF helper compatível
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

// upload simples
function save_uploaded_image($field){
	$uploads = __DIR__ . '/../private/uploads/rooms/';
	if(!is_dir($uploads)) @mkdir($uploads, 0755, true);
	if(empty($_FILES[$field]) || $_FILES[$field]['error'] !== UPLOAD_ERR_OK) return null;
	$tmp = $_FILES[$field]['tmp_name'];
	$orig = $_FILES[$field]['name'];
	$ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
	$allowed = ['jpg','jpeg','png','gif'];
	if(!in_array($ext, $allowed, true)) return null;
	$name = time() . '_' . bin2hex(random_bytes(6)) . '.' . $ext;
	if(move_uploaded_file($tmp, $uploads . $name)) return $name;
	return null;
}

// Handlers POST (JSON)
if($_SERVER['REQUEST_METHOD'] === 'POST'){
	header('Content-Type: application/json; charset=utf-8');
	$action = $_POST['action'] ?? '';
	$token = $_POST['csrf'] ?? '';
	if(!csrf_ok($token)){ echo json_encode(['ok'=>false,'msg'=>'CSRF']); exit; }

	try {
		if($action === 'admin_add_room'){
			$nome = trim($_POST['nome'] ?? '');
			$cap = (int)($_POST['capacidade'] ?? 0);
			$estado = $_POST['estado'] ?? 'disponivel'; // disponibilidade operacional
			if($nome === '' || $cap <= 0) { echo json_encode(['ok'=>false,'msg'=>'Dados']); exit; }
			$foto = save_uploaded_image('foto');
			// NOVO: inserir com estado_registo = 'disponivel' por omissão
			$st = $pdo->prepare("INSERT INTO salas (nome, capacidade, estado, foto, estado_registo) VALUES (:n,:c,:e,:f,'disponivel')");
			$st->execute([':n'=>$nome,':c'=>$cap,':e'=>$estado,':f'=>$foto]);
			$newRoomId = (int)$pdo->lastInsertId();
			if(isset($logger) && method_exists($logger,'audit_sala_admin')){
				$adminId = $_SESSION['user_id'] ?? null;
				$logger->audit_sala_admin($adminId,'SALA_CRIADA',"Sala {$newRoomId} criada");
			}
			echo json_encode(['ok'=>true]); exit;
		}

		if($action === 'admin_delete_room'){
			$id = (int)($_POST['id'] ?? 0);
			if($id <= 0){ echo json_encode(['ok'=>false]); exit; }

			// Em vez de DELETE físico, vamos marcar como eliminado
			// OPCIONAL: se quiseres, podes também eliminar a foto do disco
			$st = $pdo->prepare("SELECT foto FROM salas WHERE id=:id");
			$st->execute([':id'=>$id]); $row = $st->fetch();
			if(!empty($row['foto'])){
				@unlink(__DIR__ . '/../private/uploads/rooms/' . $row['foto']);
			}

			$del = $pdo->prepare("UPDATE salas SET estado_registo = 'eliminado' WHERE id = :id");
			$del->execute([':id'=>$id]);
			if(isset($logger) && method_exists($logger,'audit_sala_admin')){
				$adminId = $_SESSION['user_id'] ?? null;
				$logger->audit_sala_admin($adminId,'SALA_ELIMINADA',"Sala {$id} eliminada");
			}
			echo json_encode(['ok'=>true]); exit;
		}

		if($action === 'admin_edit_room'){
			$id = (int)($_POST['id'] ?? 0);
			$nome = trim($_POST['nome'] ?? '');
			$cap = (int)($_POST['capacidade'] ?? 0);
			$estado = $_POST['estado'] ?? 'disponivel';
			if($id<=0 || $nome==='' || $cap<=0){ echo json_encode(['ok'=>false,'msg'=>'Dados']); exit; }

			// Garantir que não editas salas "eliminadas" (opcional, mas recomendável)
			$st = $pdo->prepare("SELECT foto, estado_registo FROM salas WHERE id=:id");
			$st->execute([':id'=>$id]); $r=$st->fetch();
			if(!$r || ($r['estado_registo'] ?? 'disponivel') === 'eliminado'){
				echo json_encode(['ok'=>false,'msg'=>'Sala eliminada, não pode ser editada']); exit;
			}

			$foto = $r['foto'] ?? null;
			$new = save_uploaded_image('foto');
			if($new){
				if($foto) @unlink(__DIR__ . '/../private/uploads/rooms/' . $foto);
				$foto = $new;
			}
			$up = $pdo->prepare("UPDATE salas SET nome=:n, capacidade=:c, estado=:e, foto=:f WHERE id=:id");
			$up->execute([':n'=>$nome,':c'=>$cap,':e'=>$estado,':f'=>$foto,':id'=>$id]);
			if(isset($logger) && method_exists($logger,'audit_sala_admin')){
				$adminId = $_SESSION['user_id'] ?? null;
				$logger->audit_sala_admin($adminId,'SALA_ATUALIZADA',"Sala {$id} atualizada");
			}
			echo json_encode(['ok'=>true]); exit;
		}

		echo json_encode(['ok'=>false,'msg'=>'Ação desconhecida']); exit;
	} catch(Exception $ex){
		if(isset($GLOBALS['logger'])) $GLOBALS['logger']->error('admin_rooms: '.$ex->getMessage());
		echo json_encode(['ok'=>false,'msg'=>'Erro interno']); exit;
	}
}

// listar salas com paginação + pesquisa
$params = [];
$sqlBase = "FROM salas WHERE estado_registo != 'eliminado'";

// aplicar filtro de pesquisa (por nome)
$p = new Paginator($_GET, 5); // 5 salas por página
if($p->hasSearch()){
	$sqlBase .= " AND nome LIKE :q";
	$params[':q'] = '%'.$p->getSearch().'%';
}

// contar total
$stmtCount = $pdo->prepare("SELECT COUNT(*) ".$sqlBase);
$stmtCount->execute($params);
$p->setTotal((int)$stmtCount->fetchColumn());

// buscar registos desta página
$sqlList = "SELECT id,nome,capacidade,estado,foto ".$sqlBase." ORDER BY nome ".$p->limitSql();
$stmt = $pdo->prepare($sqlList);
$stmt->execute($params);
$salas = $stmt->fetchAll(PDO::FETCH_ASSOC);

// usar layout admin (NÃO colocar <html>/<head>/<body> aqui)
render_admin_page('Gerir Salas', function() use ($salas, $csrf, $p){
	?>
	<h2>Salas</h2>

	<!-- barra de pesquisa simples -->
	<?php echo $p->renderSearchForm('Procurar sala...', 'q'); ?>

	<form id="addForm" enctype="multipart/form-data" style="margin-bottom:12px;">
	  <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf); ?>">
	  <input type="hidden" name="action" value="admin_add_room">
	  <input name="nome" placeholder="Nome" required>
	  <input name="capacidade" type="number" value="10" min="1" style="width:90px;">
	  <select name="estado">
	    <option value="disponivel">Disponível</option>
	    <option value="indisponivel">Indisponível</option>
	    <option value="brevemente">Brevemente</option>
	  </select>
	  <input type="file" name="foto" accept="image/*">
	  <button class="btn-admin" type="submit">Adicionar</button>
	</form>

	<table class="table">
	  <thead><tr><th>Foto</th><th>Nome</th><th>Capacidade</th><th>Estado</th><th>Ações</th></tr></thead>
	  <tbody id="roomsBody">
	  <?php foreach($salas as $s): ?>
	    <tr data-id="<?php echo (int)$s['id']; ?>">
	      <td class="thumb-cell">
				<?php if($s['foto']): ?>
						<img src="/room_image.php?file=<?php echo rawurlencode($s['foto']); ?>" alt="foto sala">
					<?php endif; ?>
	      </td>
	      <td class="name"><?php echo htmlspecialchars($s['nome']); ?></td>
	      <td class="cap"><?php echo (int)$s['capacidade']; ?></td>
	      <td class="estado"><?php echo htmlspecialchars($s['estado']); ?></td>
	      <td>
	        <button class="btn-admin edit">Editar</button>
	        <button class="btn-admin danger delete">Eliminar</button>
	      </td>
	    </tr>
	  <?php endforeach; ?>
	  </tbody>
	</table>

	<!-- links de paginação -->
	<?php echo $p->renderLinks('p'); ?>

	<script>
	const postUrl = '/index.php';
	function sendFormData(fd, cb){
	  fetch(postUrl, { method:'POST', body: fd, credentials: 'include' })
	    .then(r=>r.json()).then(cb).catch(()=>cb({ok:false,msg:'Comunicação'}));
	}
	document.getElementById('addForm').addEventListener('submit', function(e){
	  e.preventDefault();
	  const fd = new FormData(this);
	  sendFormData(fd, function(res){ if(res.ok) location.reload(); else alert(res.msg||'Erro'); });
	});
	document.getElementById('roomsBody').addEventListener('click', function(e){
	  const tr = e.target.closest('tr');
	  if(!tr) return;
	  const id = tr.getAttribute('data-id');
	  if(e.target.classList.contains('delete')){
	    if(!confirm('Eliminar sala?')) return;
	    const fd = new FormData(); fd.append('action','admin_delete_room'); fd.append('id', id);
	    fd.append('csrf', document.querySelector('input[name=csrf]').value);
	    sendFormData(fd, function(res){ if(res.ok) location.reload(); else alert(res.msg||'Erro'); });
	    return;
	  }
	  if(e.target.classList.contains('edit')){
	    const nameEl = tr.querySelector('.name').textContent.trim();
	    const capEl = tr.querySelector('.cap').textContent.trim();
	    const estadoEl = tr.querySelector('.estado').textContent.trim();
	    const imgEl = tr.querySelector('td.thumb-cell img');
	    const imgSrc = imgEl ? imgEl.src : '';
	    const original = tr.innerHTML;
	    const csrfVal = document.querySelector('input[name=csrf]').value;
	    tr.innerHTML = '<td colspan="5">' +
	      '<form class="inlineEdit" enctype="multipart/form-data">' +
	      '<input type="hidden" name="csrf" value="' + csrfVal + '">' +
	      '<input type="hidden" name="action" value="admin_edit_room">' +
	      '<input type="hidden" name="id" value="' + id + '">' +
	      '<div style="display:flex;gap:10px;align-items:center;">' +
	        (imgSrc ? ('<div><img src="' + imgSrc + '" style="height:64px;border-radius:6px;"></div>') : '<div style="width:64px;height:64px;background:#f3f4f6;border-radius:6px;"></div>') +
	        '<div style="flex:1;display:flex;gap:8px;align-items:center;">' +
	          '<input name="nome" value="' + escapeHtml(nameEl) + '" required>' +
	          '<input name="capacidade" type="number" value="' + escapeHtml(capEl) + '" style="width:80px;">' +
	          '<select name="estado"><option value="disponivel">Disponível</option><option value="indisponivel">Indisponível</option><option value="brevemente">Brevemente</option></select>' +
	          '<input type="file" name="foto" accept="image/*">' +
	        '</div>' +
	        '<div style="display:flex;flex-direction:column;gap:6px;">' +
	          '<button type="submit" class="btn-admin">Guardar</button>' +
	          '<button type="button" class="btn-admin danger cancel">Cancelar</button>' +
	        '</div>' +
	      '</div>' +
	      '</form>' +
	      '</td>';
	    const sel = tr.querySelector('select[name=estado]');
	    if(sel) sel.value = estadoEl;
	    tr.querySelector('.cancel').addEventListener('click', function(){
	      tr.innerHTML = original;
	    });
	    tr.querySelector('.inlineEdit').addEventListener('submit', function(ev){
	      ev.preventDefault();
	      const fd = new FormData(this);
	      sendFormData(fd, function(res){
	        if(res.ok) location.reload(); else alert(res.msg||'Erro');
	      });
	    });
	  }
	});
	function escapeHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
	</script>
	<?php
});
