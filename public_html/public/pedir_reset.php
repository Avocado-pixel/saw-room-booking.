<?php
// Página "pedir recuperação de senha":
//
// - Em GET mostra um formulário onde o utilizador introduz o email registado.
// - Em POST valida o CSRF e o email, gera um código de 6 dígitos,
//   guarda o hash e validade na BD e envia um email com o código + link.

if(!isset($_SESSION)) session_start();
if(!isset($pdo)){
	require_once __DIR__ . '/../bootstrap.php';
}
require_once __DIR__ . '/../core/security.php';

// Helper para guardar mensagem flash e redirecionar de volta ao formulário "pedir"
function flash_redirect_pedir(string $type, string $msg): void {
	$_SESSION[$type] = $msg;
	header('Location: /index.php?page=pedir_reset');
	exit;
}

// Tratamento do pedido de recuperação (POST)
if($_SERVER['REQUEST_METHOD'] === 'POST'){
	$post = \Security::clean_array($_POST);

	// CSRF
	if(!\Security::verify_csrf($post['csrf'] ?? '')){
		@file_put_contents(__DIR__ . '/../private/logs/server_error.txt',
			'['.date('Y-m-d H:i:s').'] ['.($_SERVER['REMOTE_ADDR'] ?? 'cli').'] [RECOVER_PDIR] CSRF_FAIL'.PHP_EOL,
			FILE_APPEND|LOCK_EX
		);
		flash_redirect_pedir('flash_error', 'Sessão inválida. Tente novamente.');
	}

	// Email fornecido pelo utilizador
	$email = trim($post['email'] ?? '');
	if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
		flash_redirect_pedir('flash_error','Email inválido.');
	}

	// Procurar utilizador com esse email (sem revelar se existe ou não)
	$st = $pdo->prepare("SELECT id,nome FROM utilizadores WHERE email = :e LIMIT 1");
	$st->execute([':e'=>$email]);
	$user = $st->fetch();

	if(!$user){
		// Não revelar se o email existe: resposta sempre genérica
		@file_put_contents(__DIR__ . '/../private/logs/server_error.txt',
			'['.date('Y-m-d H:i:s').'] ['.($_SERVER['REMOTE_ADDR'] ?? 'cli').'] [RECOVER_NOUSER] '.$email.PHP_EOL,
			FILE_APPEND|LOCK_EX
		);
		$_SESSION['flash_success'] = 'Se o email estiver registado, recebeu instruções.';
		header('Location: /index.php?page=reset_password&email=' . urlencode($email));
		exit;
	}

	// Gerar código numérico de 6 dígitos e respetivo hash HMAC
	$code = random_int(100000,999999);
	$codeHash = hash_hmac('sha256', (string)$code, APP_KEY);
	$exp = date('Y-m-d H:i:s', time() + 15*60);

	// Guardar hash e data de expiração do pedido (15 minutos)
	$upd = $pdo->prepare("UPDATE utilizadores SET token_recuperacao = :t, token_recuperacao_expira = :exp WHERE id = :id");
	$upd->execute([':t'=>$codeHash, ':exp'=>$exp, ':id'=>$user['id']]);

	// Link direto para a página de redefinição de senha (reset)
	$host = ($_SERVER['HTTP_HOST'] ?? 'saw.pt');
	$link = 'https://' . $host . '/index.php?page=recuperar_senha_reset&email=' . urlencode($email);

	// Enviar email com o código e o link de redefinição
	try {
		require_once __DIR__ . '/../core/Mailer.php';
		$mailer = new Mailer($logger ?? null);
		$subject = 'Recuperação de senha - SAW';
		$body = "Olá {$user['nome']},\n\nFoi pedido um código para recuperar a sua password. Código (válido 15 minutos): {$code}\n\nPara redefinir a senha, aceda a:\n{$link}\n\nSe não pediu, ignore esta mensagem.";
		$mailer->sendMail($email, $user['nome'], $subject, $body);
	} catch(Exception $e){
		@file_put_contents(__DIR__ . '/../private/logs/server_error.txt',
			'['.date('Y-m-d H:i:s').'] [RECOVER_MAIL_ERR]: '.$e->getMessage().PHP_EOL,
			FILE_APPEND|LOCK_EX
		);
	}

	if(isset($logger) && method_exists($logger,'audit_recovery_request')){
		$logger->audit_recovery_request((int)$user['id'], $email);
	}

	$_SESSION['pw_recovery_email'] = $email;
	$_SESSION['flash_success'] = 'Se o email estiver registado, recebeu um código.';
	header('Location: /index.php?page=reset_password&email=' . urlencode($email));
	exit;
}

// GET – formulário simples
$flashErr = $_SESSION['flash_error'] ?? null; if($flashErr) unset($_SESSION['flash_error']);
$flashOk  = $_SESSION['flash_success'] ?? null; if($flashOk) unset($_SESSION['flash_success']);
?>
<!doctype html>
<html lang="pt">
<head>
<meta charset="utf-8">
<title>Pedir recuperação de senha - SAW</title>
<link rel="stylesheet" href="/assets/css/style_public.css">
<style>
.form-wrap{ max-width:520px;margin:36px auto;background:#fff;padding:20px;border-radius:10px;box-shadow:0 8px 24px rgba(2,6,23,0.06); }
.form-row{ margin-bottom:12px; display:flex; flex-direction:column; gap:6px; }
.btn{ padding:10px 12px;border-radius:8px;border:0; cursor:pointer; font-weight:600; }
.btn-primary{ background:#0d6efd;color:#fff; }
.msg{ margin-top:10px; font-size:0.95rem; }
.small{ font-size:0.9rem; color:#475569; margin-top:8px; }
</style>
</head>
<body>
<header class="topbar">
  <div class="logo">SAW — Recuperação</div>
</header>
<main class="container" style="max-width:720px;margin:90px auto 40px;">
  <div class="form-wrap" role="main">
    <h2>Pedir recuperação de senha</h2>

    <?php if($flashErr): ?>
      <div class="msg" style="color:#9f1239;"><?php echo htmlspecialchars($flashErr); ?></div>
    <?php endif; ?>
    <?php if($flashOk): ?>
      <div class="msg" style="color:#065f46;"><?php echo htmlspecialchars($flashOk); ?></div>
    <?php endif; ?>

	<form method="post" action="/index.php?page=pedir_reset">
      <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
      <div class="form-row">
        <label>Email registado</label>
        <input type="email" name="email" required>
      </div>
      <div><button class="btn btn-primary" type="submit">Enviar código</button></div>
    </form>
    <div class="small">O código é válido por 15 minutos.</div>

	<div style="margin-top:12px;"><a href="/index.php?page=login">Voltar ao login</a></div>
	<div style="margin-top:12px;"><a href="/index.php?page=reset_password">Já tenho o código</a></div>
  </div>
</main>
</body>
</html>
