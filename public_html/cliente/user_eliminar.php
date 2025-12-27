<?php
/**
 * Página para o próprio utilizador pedir a eliminação da conta.
 *
 * Fluxo em dois passos, controlado por POST local com o campo "stage":
 *   - request_account_delete: gera um código de 6 dígitos, guarda o hash
 *     (HMAC com APP_KEY) e o tempo de expiração na sessão, e envia esse
 *     código por email ao utilizador;
 *   - confirm_account_delete: valida o código, marca o utilizador como
 *     "eliminado" na base de dados e termina a sessão (logout).
 *
 * Cada etapa é protegida por token CSRF e todos os pedidos são limpos com
 * Security::clean_array. As ações são registadas em Logger::audit_user
 * (ACCOUNT_DELETE_REQUEST, ACCOUNT_DELETED).
 */

// Garante sessão ativa e que o utilizador esteja autenticado
if(!isset($_SESSION)) session_start();
if(empty($_SESSION['user_id'])) {
	header('Location: /index.php?page=login');
	exit;
}
if(!isset($pdo)) require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../core/security.php';

$uid = (int)$_SESSION['user_id'];
$isAdmin = (($_SESSION['perfil'] ?? '') === 'admin');
if($isAdmin){
	require_once __DIR__ . '/../core/AdminLayout.php';
} else {
	require_once __DIR__ . '/../core/ClientLayout.php';
}

// --- NOVO: tratar POST local (pedir código / confirmar eliminação) ---
if($_SERVER['REQUEST_METHOD'] === 'POST'){
	$post  = \Security::clean_array($_POST);
	$stage = $post['stage'] ?? '';

	if(!\Security::verify_csrf($post['csrf'] ?? '')){
		$_SESSION['flash_error'] = 'Sessão inválida. Tente novamente.';
		header('Location: /index.php?page=user_eliminar');
		exit;
	}

	// Pedir código para eliminar conta
	if($stage === 'request_account_delete'){
		$code = random_int(100000, 999999);
		$_SESSION['account_delete_code_hash']   = hash_hmac('sha256',(string)$code, APP_KEY);
		$_SESSION['account_delete_code_expire'] = time() + 15*60;

		$st = $pdo->prepare("SELECT email,nome FROM utilizadores WHERE id = :id LIMIT 1");
		$st->execute([':id'=>$uid]); $u = $st->fetch(PDO::FETCH_ASSOC);
		if(!$u){
			$_SESSION['flash_error'] = 'Utilizador não encontrado.';
			header('Location: /index.php?page=user_eliminar'); exit;
		}

		try {
			require_once __DIR__ . '/../core/Mailer.php';
			$mailer  = new Mailer($logger ?? null);
			$subject = 'Confirmar eliminação de conta - SAW';
			$body    = "Olá {$u['nome']},\n\nO seu código para confirmar a eliminação da conta é: {$code}\nÉ válido por 15 minutos.\n\nSe não pediu esta eliminação, ignore este email.";
			$mailer->sendMail($u['email'], $u['nome'], $subject, $body);
		} catch(Exception $me){
			if(isset($logger) && method_exists($logger,'error')){
				$logger->error('Falha no envio de email de eliminação de conta: '.$me->getMessage());
			}
		}

		// NOVO: logar pedido de eliminação
		if(isset($logger) && method_exists($logger,'audit_user')){
			$logger->audit_user($uid,'ACCOUNT_DELETE_REQUEST','Pedido de código para eliminação de conta');
		}

		$_SESSION['flash_success'] = 'Enviámos um código para o seu email para confirmar a eliminação da conta.';
		header('Location: /index.php?page=user_eliminar'); exit;
	}

	// Confirmar eliminação de conta
	if($stage === 'confirm_account_delete'){
		$code = $post['code'] ?? '';
		if(!preg_match('/^\d{6}$/', $code)){
			$_SESSION['flash_error'] = 'Código inválido.'; 
			header('Location: /index.php?page=user_eliminar'); exit;
		}

		$hash   = $_SESSION['account_delete_code_hash']   ?? '';
		$expire = $_SESSION['account_delete_code_expire'] ?? 0;

		if($hash === '' || $expire < time()){
			$_SESSION['flash_error'] = 'Código expirado. Peça novo código.'; 
			header('Location: /index.php?page=user_eliminar'); exit;
		}
		if(!hash_equals($hash, hash_hmac('sha256',(string)$code, APP_KEY))){
			$_SESSION['flash_error'] = 'Código incorreto.'; 
			header('Location: /index.php?page=user_eliminar'); exit;
		}

		try {
			$upd = $pdo->prepare("UPDATE utilizadores SET estado = 'eliminado' WHERE id = :id");
			$upd->execute([':id'=>$uid]);

			unset($_SESSION['account_delete_code_hash'], $_SESSION['account_delete_code_expire']);

			// já existia, mantemos:
			if(isset($logger) && method_exists($logger,'audit_user')){
				$logger->audit_user($uid,'ACCOUNT_DELETED','Conta marcada como eliminada pelo utilizador');
			}

			$_SESSION['flash_success'] = 'A sua conta foi marcada como eliminada.';
			header('Location: /index.php?action=logout'); exit;
		} catch(Exception $e){
			$_SESSION['flash_error'] = 'Erro ao eliminar conta.';
			header('Location: /index.php?page=user_eliminar'); exit;
		}
	}

	// stage desconhecido
	$_SESSION['flash_error'] = 'Ação inválida.';
	header('Location: /index.php?page=user_eliminar');
	exit;
}

// flash (depois dos POSTs)
$flashErr = $_SESSION['flash_error'] ?? null; if($flashErr) unset($_SESSION['flash_error']);
$flashOk  = $_SESSION['flash_success'] ?? null; if($flashOk) unset($_SESSION['flash_success']);

$renderFn = function() use ($flashErr, $flashOk){
	?>
	<div style="max-width:640px;margin:0 auto;">
	  <h1 style="margin:0 0 12px 0;font-size:1.7rem;">Eliminar conta</h1>
	  <p style="margin:0 0 14px 0;font-size:0.95rem;color:#6b7280;">
	    A eliminação é permanente a nível de acesso. Os seus dados podem manter‑se por razões de histórico e reservas.
	  </p>

	  <?php if($flashErr): ?>
	    <div style="margin-bottom:12px;padding:10px 12px;border-radius:8px;background:#fef2f2;color:#b91c1c;font-size:0.9rem;">
	      <?php echo htmlspecialchars($flashErr); ?>
	    </div>
	  <?php endif; ?>
	  <?php if($flashOk): ?>
	    <div style="margin-bottom:12px;padding:10px 12px;border-radius:8px;background:#ecfdf3;color:#166534;font-size:0.9rem;">
	      <?php echo htmlspecialchars($flashOk); ?>
	    </div>
	  <?php endif; ?>

	  <div style="background:#ffffff;border-radius:10px;border:1px solid #e5e7eb;padding:16px;box-shadow:0 4px 16px rgba(15,23,42,0.06);">
	    <h2 style="margin:0 0 8px 0;font-size:1.05rem;color:#9f1239;">Passo 1 — Pedir código</h2>
	    <p style="margin:0 0 10px 0;font-size:0.88rem;color:#6b7280;">
	      Enviaremos um código de 6 dígitos para o seu email. Só com esse código a eliminação será confirmada.
	    </p>
	    <form method="post" action="/index.php?page=user_eliminar" style="margin-bottom:16px;">
	      <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
	      <input type="hidden" name="stage" value="request_account_delete">
	      <button class="client-btn" type="submit" style="background:#9f1239;color:#fff;width:100%;max-width:260px;">
	        Pedir código para eliminar conta
	      </button>
	    </form>

	    <h2 style="margin:0 0 8px 0;font-size:1.05rem;">Passo 2 — Confirmar eliminação</h2>
	    <p style="margin:0 0 10px 0;font-size:0.88rem;color:#6b7280;">
	      Depois de receber o código, introduza-o em baixo para concluir a eliminação.
	    </p>
	    <form method="post" action="/index.php?page=user_eliminar">
	      <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
	      <input type="hidden" name="stage" value="confirm_account_delete">
	      <div class="client-form-row">
	        <label>Código de confirmação (6 dígitos)</label>
	        <input name="code" maxlength="6" pattern="\d{6}" required placeholder="Ex.: 123456">
	      </div>
	      <button class="client-btn" type="submit" style="background:#ef4444;color:#fff;width:100%;max-width:260px;">
	        Confirmar eliminação
	      </button>
	    </form>
	  </div>
	</div>
	<?php
};

if($isAdmin){
	render_admin_page('Eliminar conta', $renderFn);
} else {
	render_client_page('Eliminar conta', $renderFn);
}
