<?php
// Página de redefinição de senha (segunda parte do fluxo de recuperação).
//
// - Em GET mostra o formulário para introduzir email, código e nova senha.
// - Em POST valida CSRF, email, código e força de senha.
// - Se o código estiver correto e dentro do prazo, atualiza a password e limpa o token.

if(!isset($_SESSION)) session_start();
if(!isset($pdo)){
	require_once __DIR__ . '/../bootstrap.php';
}
require_once __DIR__ . '/../core/security.php';

// Garantir que a classe Validator está carregada (para sanitizar e validar password)
if(!class_exists('Validator')){
	require_once __DIR__ . '/../core/Validator.php';
}

// Helper para definir mensagem flash e redirecionar para a página indicada
function flash_redirect_reset(string $page, string $type, string $msg): void {
	$_SESSION[$type] = $msg;
	// Redireciona para as páginas através do roteador index.php?page=...
	if($page === 'recuperar_senha_reset'){
		header('Location: /index.php?page=reset_password');
	} elseif($page === 'login'){
		header('Location: /index.php?page=login');
	} else {
		// fallback genérico (devia ser raro)
		header('Location: /index.php?page=reset_password');
	}
	exit;
}

// Email a pré-preencher no formulário (do link ou sessão)
$prefillEmail = $_GET['email'] ?? ($_SESSION['pw_recovery_email'] ?? '');

// POST: submissão do formulário de redefinição
if($_SERVER['REQUEST_METHOD'] === 'POST'){
	$post = \Security::clean_array($_POST);

	if(!\Security::verify_csrf($post['csrf'] ?? '')){
		@file_put_contents(__DIR__ . '/../private/logs/server_error.txt',
			'['.date('Y-m-d H:i:s').'] ['.($_SERVER['REMOTE_ADDR'] ?? 'cli').'] [RECOVER_RESET] CSRF_FAIL'.PHP_EOL,
			FILE_APPEND|LOCK_EX
		);
		flash_redirect_reset('recuperar_senha_reset','flash_error','Sessão inválida. Tente novamente.');
	}

	// Usar Validator para sanitizar o email de entrada
	$emailRaw = $post['email'] ?? $prefillEmail;
	$email    = \Validator::sanitizeEmail($emailRaw);
	$code  = $post['code'] ?? '';
	$pass  = $post['password'] ?? '';
	$passc = $post['password_confirm'] ?? '';

	if(!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/^\d{6}$/', $code)){
		flash_redirect_reset('recuperar_senha_reset','flash_error','Dados inválidos.');
	}
	// NOVO: password forte para reset
	if($pass === '' || $pass !== $passc || !\Validator::validatePasswordStrong($pass)){
		flash_redirect_reset(
			'recuperar_senha_reset',
			'flash_error',
			'Senha inválida. Deve ter pelo menos 10 caracteres, incluindo maiúsculas, minúsculas, números e símbolos.'
		);
	}

	$st = $pdo->prepare("SELECT id,token_recuperacao,token_recuperacao_expira FROM utilizadores WHERE email = :e LIMIT 1");
	$st->execute([':e'=>$email]);
	$user = $st->fetch();
	if(!$user){
		flash_redirect_reset('recuperar_senha_reset','flash_error','Código ou email inválido.');
	}
	if(empty($user['token_recuperacao']) || empty($user['token_recuperacao_expira']) || strtotime($user['token_recuperacao_expira']) < time()){
		flash_redirect_reset('recuperar_senha_reset','flash_error','Código expirado. Peça um novo código.');
	}
	$expected = hash_hmac('sha256', (string)$code, APP_KEY);
	if(!hash_equals($expected, $user['token_recuperacao'])){
		@file_put_contents(__DIR__ . '/../private/logs/server_error.txt',
			'['.date('Y-m-d H:i:s').'] [RECOVER_BADCODE]: email='.$email.PHP_EOL,
			FILE_APPEND|LOCK_EX
		);
		flash_redirect_reset('recuperar_senha_reset','flash_error','Código inválido.');
	}

	// Hash seguro da nova senha (PHP trata automaticamente do salt).
	// A função password_hash(), da própria linguagem PHP, gera um salt
	// aleatório e único e guarda tudo (hash + salt + custo) no campo password.
	$hash = password_hash($pass, PASSWORD_BCRYPT);
	try {
		$upd = $pdo->prepare("UPDATE utilizadores SET password = :p, token_recuperacao = NULL, token_recuperacao_expira = NULL WHERE id = :id");
		$upd->execute([':p'=>$hash, ':id'=>$user['id']]);

		// NOVO: registar conclusão da recuperação
		if(isset($logger) && method_exists($logger,'audit_recovery_complete')){
			$logger->audit_recovery_complete((int)$user['id'], $email);
		}

		unset($_SESSION['pw_recovery_email']);
		flash_redirect_reset('login','flash_success','Senha alterada com sucesso. Inicie sessão.');
	} catch(PDOException $e){
		@file_put_contents(__DIR__ . '/../private/logs/server_error.txt',
			'['.date('Y-m-d H:i:s').'] [RECOVER_SET_ERR]: '.$e->getMessage().PHP_EOL,
			FILE_APPEND|LOCK_EX
		);
		flash_redirect_reset('recuperar_senha_reset','flash_error','Erro no servidor. Tente novamente mais tarde.');
	}
}

// GET: formulário
$flashErr = $_SESSION['flash_error'] ?? null; if($flashErr) unset($_SESSION['flash_error']);
$flashOk  = $_SESSION['flash_success'] ?? null; if($flashOk) unset($_SESSION['flash_success']);
?>
<!doctype html>
<html lang="pt">
<head>
<meta charset="utf-8">
<title>Redefinir Senha - SAW</title>
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
    <h2>Redefinir senha</h2>

    <?php if($flashErr): ?>
      <div class="msg" style="color:#9f1239;"><?php echo htmlspecialchars($flashErr); ?></div>
    <?php endif; ?>
    <?php if($flashOk): ?>
      <div class="msg" style="color:#065f46;"><?php echo htmlspecialchars($flashOk); ?></div>
    <?php endif; ?>

	<form method="post" action="/index.php?page=reset_password">
      <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
      <div class="form-row">
        <label>Email registado</label>
        <input type="email" name="email" value="<?php echo htmlspecialchars($prefillEmail); ?>" required>
      </div>
      <div class="form-row">
        <label>Código recebido (6 dígitos)</label>
        <input type="text" name="code" maxlength="6" pattern="\d{6}" required>
      </div>
      <div class="form-row">
        <label>Nova senha</label>
        <input type="password" name="password" required>
      </div>
      <div class="form-row">
        <label>Confirmar nova senha</label>
        <input type="password" name="password_confirm" required>
      </div>
      <div><button class="btn btn-primary" type="submit">Definir Nova Senha</button></div>
    </form>

    <div class="small">O código é válido por 15 minutos.</div>
	<div style="margin-top:12px;"><a href="/index.php?page=login">Voltar ao login</a></div>
  </div>
</main>
</body>
</html>
