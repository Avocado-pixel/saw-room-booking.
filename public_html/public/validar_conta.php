<?php
// Página de validação de conta por código enviado por email.
//
// Fluxo resumido:
// - Em GET mostra um formulário para o utilizador introduzir email + código.
// - Em POST valida o CSRF, carrega o utilizador e verifica o código de 6 dígitos.
// - Se tudo estiver correto, marca a conta como "disponivel" e limpa o token.

// Garantir sessão iniciada e bootstrap carregado (PDO, logger, etc.)
if(!isset($_SESSION)) session_start();
if(!isset($pdo)){
	require_once __DIR__ . '/../bootstrap.php';
}
require_once __DIR__ . '/../core/security.php';

// Mensagens flash (erro/sucesso) vindas de redireções anteriores
$flashErr = $_SESSION['flash_error'] ?? null; if($flashErr) unset($_SESSION['flash_error']);
$flashOk  = $_SESSION['flash_success'] ?? null; if($flashOk) unset($_SESSION['flash_success']);

// PROCESSO POST: validar código submetido no formulário
if($_SERVER['REQUEST_METHOD'] === 'POST'){
	$post = \Security::clean_array($_POST);

	if(!\Security::verify_csrf($post['csrf'] ?? '')){
		$_SESSION['flash_error'] = 'Sessão inválida. Tente novamente.';
		header('Location: /index.php?page=validar_conta');
		exit;
	}

	$email = trim($post['email'] ?? '');
	$code  = trim($post['code'] ?? '');

	if(!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/^\d{6}$/', $code)){
		$_SESSION['flash_error'] = 'Dados inválidos.';
		header('Location: /index.php?page=validar_conta');
		exit;
	}

	// Procura utilizador pelo email e traz estado + token de validação
	$st = $pdo->prepare("SELECT id,estado,token_validacao_email,token_validacao_email_expira FROM utilizadores WHERE email = :e LIMIT 1");
	$st->execute([':e'=>$email]);
	$user = $st->fetch(PDO::FETCH_ASSOC);

	if(!$user){
		$_SESSION['flash_error'] = 'Utilizador não encontrado.';
		header('Location: /index.php?page=validar_conta');
		exit;
	}

	// Se a conta já estiver ativa, não é preciso validar novamente
	if(($user['estado'] ?? 'pendente') === 'disponivel'){
		$_SESSION['flash_success'] = 'A sua conta já está ativa. Pode iniciar sessão.';
		header('Location: /index.php?page=login');
		exit;
	}

	// Verificar se existe token de validação e se ainda não expirou
	if(empty($user['token_validacao_email']) || empty($user['token_validacao_email_expira'])){
		$_SESSION['flash_error'] = 'Não existe um pedido de validação ativo. Faça novo registo ou contacte suporte.';
		header('Location: /index.php?page=validar_conta');
		exit;
	}
	if(strtotime($user['token_validacao_email_expira']) < time()){
		$_SESSION['flash_error'] = 'Código expirado. Faça novo registo ou peça novo código.';
		header('Location: /index.php?page=validar_conta');
		exit;
	}

	// Compara o HMAC do código fornecido com o token guardado na BD
	$expected = hash_hmac('sha256', (string)$code, APP_KEY);
	if(!hash_equals($expected, $user['token_validacao_email'])){
		$_SESSION['flash_error'] = 'Código inválido.';
		header('Location: /index.php?page=validar_conta');
		exit;
	}

	// Tudo OK: ativar conta e limpar o token de validação
	try {
		$upd = $pdo->prepare("
			UPDATE utilizadores
			   SET estado = 'disponivel',
			       token_validacao_email = NULL,
			       token_validacao_email_expira = NULL
			 WHERE id = :id
		");
		$upd->execute([':id'=>$user['id']]);

		if(isset($logger) && method_exists($logger,'audit_user')){
			$logger->audit_user($user['id'],'ACCOUNT_ACTIVATED','Conta validada via código de email');
		}

		$_SESSION['flash_success'] = 'Conta validada com sucesso. Já pode iniciar sessão.';
		header('Location: /index.php?page=login');
		exit;
	} catch (PDOException $e){
		@file_put_contents(__DIR__ . '/../private/logs/server_error.txt',
			'['.date('Y-m-d H:i:s').'] [VAL_CONTA_ERR]: '.$e->getMessage().PHP_EOL,
			FILE_APPEND | LOCK_EX
		);
		$_SESSION['flash_error'] = 'Erro no servidor. Tente novamente mais tarde.';
		header('Location: /index.php?page=validar_conta');
		exit;
	}
}

// GET: mostrar formulário
?>
<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8">
  <title>Validar Conta - SAW</title>
  <link rel="stylesheet" href="/assets/css/style_public.css">
  <style>
    .auth-wrap{ max-width:520px; margin:36px auto; background:#fff; padding:20px; border-radius:10px; box-shadow:0 8px 24px rgba(2,6,23,0.06); }
    .auth-wrap h2{ margin:0 0 12px 0; }
    .form-row{ margin-bottom:12px; display:flex; flex-direction:column; gap:6px; }
    .form-row input{ padding:10px; border-radius:8px; border:1px solid #e6eef8; }
    .btn-main{ background:#0f5132; color:#fff; border:0; padding:10px 14px; border-radius:8px; cursor:pointer; width:100%; font-weight:600; }
    .msg{ margin-top:10px; font-size:0.95rem; }
  </style>
</head>
<body>
  <header class="topbar" role="navigation" aria-label="Navegação principal">
    <div class="logo">SAW — Validar Conta</div>
    <nav class="nav" aria-label="Ações">
	  <!-- Usa o roteador central index.php?page=... para não expor a estrutura interna -->
	  <a class="ghost" href="/index.php?page=login">Login</a>
	  <a class="primary" href="/index.php?page=register">Registar</a>
    </nav>
  </header>

  <main class="container" role="main">
    <div class="auth-wrap" aria-live="polite">
      <h2>Validar Conta</h2>

      <?php if($flashErr): ?>
        <div class="msg" style="color:#9f1239;"><?php echo htmlspecialchars($flashErr); ?></div>
      <?php endif; ?>
      <?php if($flashOk): ?>
        <div class="msg" style="color:#065f46;"><?php echo htmlspecialchars($flashOk); ?></div>
      <?php endif; ?>

      <p style="font-size:0.9rem;color:#475569;">
        Introduza o email que usou no registo e o código de 6 dígitos que recebeu por email.
      </p>

	<form method="post" action="/index.php?page=validar_conta">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
        <div class="form-row">
          <label>Email</label>
          <input type="email" name="email" value="<?php echo htmlspecialchars($_SESSION['pending_user_email'] ?? ''); ?>" required>
        </div>
        <div class="form-row">
          <label>Código de validação (6 dígitos)</label>
          <input type="text" name="code" maxlength="6" pattern="\d{6}" required>
        </div>
        <div style="margin-top:8px;">
          <button class="btn-main" type="submit">Validar Conta</button>
        </div>
      </form>
    </div>
  </main>
</body>
</html>
