<?php
/**
 * Registo de novos utilizadores (página pública).
 *
 * Fluxo principal:
 * - Em GET: mostra o formulário de criação de conta, com validações básicas em JavaScript
 *   (ficheiro assets/js/validations.js) apenas para ajudar o utilizador.
 * - Em POST: volta a validar tudo do lado do servidor (campos obrigatórios, formatos,
 *   password forte, NIF, telemóvel) usando Validator e Security.
 *
 * Segurança e boas práticas aplicadas:
 * - Proteção CSRF em todos os POSTs através de Security::csrf_token()/verify_csrf().
 * - Limpeza de todos os dados recebidos com Security::clean_array() antes de usar.
 * - Passwords guardadas com password_hash() (bcrypt) e verificadas com password_verify().
 * - Foto de perfil validada (tamanho, tipo MIME, ser realmente uma imagem) e guardada em
 *   private/uploads/perfis/, fora da pasta pública.
 * - Código de validação de conta gerado como número de 6 dígitos; na BD guarda-se apenas
 *   o HMAC (hash_hmac com APP_KEY), nunca o código em texto simples.
 * - Logs de auditoria de criação de conta através de Logger::audit_user().
 * - Email de validação enviado via classe Mailer, isolando toda a lógica de SMTP.
 */

// Registo de novos utilizadores.
// GET: mostra o formulário.
// POST: valida dados, grava o utilizador na BD e envia email de boas-vindas.
// Inicia sessão e carrega bootstrap se ainda não existir $pdo
if(!isset($_SESSION)) session_start();
if(!isset($pdo)){
	require_once __DIR__ . '/../bootstrap.php';
}

// Segurança/CSRF e limpeza de dados
require_once __DIR__ . '/../core/security.php';

// PROCESSAMENTO POST (quando o utilizador submete o formulário de registo)
if($_SERVER['REQUEST_METHOD'] === 'POST'){
	$input = Security::clean_array($_POST);

	// CSRF simples (mas robusto)
	if(!Security::verify_csrf($input['csrf'] ?? '')){
		$ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
		@file_put_contents(__DIR__ . '/../private/logs/server_error.txt',
			'['.date('Y-m-d H:i:s').'] [REGISTER][CSRF_FAIL] IP='.$ip.PHP_EOL,
			FILE_APPEND|LOCK_EX
		);
		unset($_SESSION['csrf_token']);
		Security::csrf_token();
		$_SESSION['flash_error'] = 'Sessão inválida ou expirada. Tente novamente.';
		header('Location: /index.php?page=register');
		exit;
	}

	// 1) Ler + sanitizar com Validator
	$nome      = \Validator::sanitizeNome($input['nome'] ?? '');
	$email     = \Validator::sanitizeEmail($input['email'] ?? '');
	$pass      = $input['password'] ?? '';
	$pass2     = $input['password_confirm'] ?? '';
	$nif       = preg_replace('/\D/','', $input['nif'] ?? '');
	$nif       = $nif === '' ? null : $nif;
	$morada    = \Validator::sanitizeMorada($input['morada'] ?? '');
	$telemovel = \Validator::sanitizeTelemovel($input['telemovel'] ?? '');

	// 2) Validações simples
	if($nome==='' || $email==='' || $pass==='' || $pass2==='' || $nif===null || $morada==='' || $telemovel===''){
		$_SESSION['flash_error'] = 'Preencha todos os campos obrigatórios.';
		header('Location: /index.php?page=register'); exit;
	}
	if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
		$_SESSION['flash_error'] = 'Email inválido.'; header('Location: /index.php?page=register'); exit;
	}
	if(!\Validator::validateName($nome)){
		$_SESSION['flash_error'] = 'Nome inválido. Indique o nome completo.'; header('Location: /index.php?page=register'); exit;
	}
	if($pass !== $pass2){
		$_SESSION['flash_error'] = 'As senhas não coincidem.'; header('Location: /index.php?page=register'); exit;
	}
	if(!\Validator::validatePasswordStrong($pass)){
		$_SESSION['flash_error'] = 'Senha fraca. Deve ter pelo menos 10 caracteres, incluindo maiúsculas, minúsculas, números e símbolos.';
		header('Location: /index.php?page=register'); exit;
	}
	if($nif !== null && !\Validator::validateNIF_PT($nif)){
		$_SESSION['flash_error'] = 'NIF inválido.'; header('Location: /index.php?page=register'); exit;
	}
	if(strlen($telemovel) < 9){
		$_SESSION['flash_error'] = 'Telemóvel inválido.'; header('Location: /index.php?page=register'); exit;
	}

	// 3) Foto de perfil (usa helper Validator::validateProfileImage)
	$fotoCheck = \Validator::validateProfileImage($_FILES['foto'] ?? null, true);
	if(!$fotoCheck['ok']){
		$_SESSION['flash_error'] = $fotoCheck['error'] ?? 'Imagem inválida.';
		header('Location: /index.php?page=register'); exit;
	}
	$ext = $fotoCheck['ext']; // 'jpg' ou 'png'

	// 4) Unicidade email/NIF
	try {
		$chk = $pdo->prepare("SELECT email,nif FROM utilizadores WHERE email = :email OR nif = :nif LIMIT 1");
		$chk->execute([':email'=>$email, ':nif'=>$nif]);
		$exists = $chk->fetch(PDO::FETCH_ASSOC);
		if($exists){
			if(!empty($exists['email']) && $exists['email'] === $email){
				$_SESSION['flash_error'] = 'Email já registado.'; header('Location: /index.php?page=register'); exit;
			}
			if(!empty($exists['nif']) && $exists['nif'] === $nif){
				$_SESSION['flash_error'] = 'NIF já registado.'; header('Location: /index.php?page=register'); exit;
			}
		}
	} catch(PDOException $e){
		@file_put_contents(__DIR__ . '/../private/logs/server_error.txt',
			'['.date('Y-m-d H:i:s').'] [REGISTER_DBCHK]: '.$e->getMessage().PHP_EOL,
			FILE_APPEND|LOCK_EX
		);
		$_SESSION['flash_error'] = 'Erro no servidor.'; header('Location: /index.php?page=register'); exit;
	}

	// 5) Guardar foto de perfil em private/uploads/perfis/
	$uploadDir = __DIR__ . '/../private/uploads/perfis/';
	if(!is_dir($uploadDir)) @mkdir($uploadDir, 0770, true);
	try {
		$filename = bin2hex(random_bytes(16)).'.'.$ext;
	} catch(Exception $ex){
		$filename = sha1($email.microtime(true)).'.'.$ext;
	}
	$targetPath = $uploadDir.$filename;
	if(!move_uploaded_file($_FILES['foto']['tmp_name'], $targetPath)){
		$_SESSION['flash_error'] = 'Erro ao guardar foto.'; header('Location: /index.php?page=register'); exit;
	}
	@chmod($targetPath, 0640);

	// 6) Inserir utilizador + gerar código de validação
	try {
		// Hash seguro da palavra-passe.
		// IMPORTANTE: password_hash() é uma função nativa do PHP que:
		// - gera automaticamente um salt aleatório e único por utilizador;
		// - guarda hash + salt + parâmetros num único campo na BD;
		// - deve ser sempre verificada com password_verify().
		$hash = password_hash($pass, PASSWORD_BCRYPT);
		$stmt = $pdo->prepare("
			INSERT INTO utilizadores (nome,email,password,nif,telemovel,morada,foto,perfil,estado)
			VALUES (:n,:e,:p,:nif,:tel,:m,:f,'utente','pendente')
		");
		$stmt->execute([
			':n'   => $nome,
			':e'   => $email,
			':p'   => $hash,
			':nif' => $nif,
			':tel' => $telemovel,
			':m'   => $morada,
			':f'   => 'private/uploads/perfis/'.$filename
		]);
		$userId = (int)$pdo->lastInsertId();

		if(isset($logger) && method_exists($logger,'audit_user')){
			$logger->audit_user($userId,'REGISTER',"Registo do utilizador {$email} (estado pendente)");
		}

		// código de validação (6 dígitos) + expiração
		$code = random_int(100000, 999999);
		$codeHash = hash_hmac('sha256', (string)$code, APP_KEY);
		$exp = date('Y-m-d H:i:s', time() + 30*60);

		$updTok = $pdo->prepare("
			UPDATE utilizadores
			   SET token_validacao_email = :t,
			       token_validacao_email_expira = :e
			 WHERE id = :id
		");
		$updTok->execute([':t'=>$codeHash, ':e'=>$exp, ':id'=>$userId]);

		// Enviar email de validação (usa Mailer)
		try {
			require_once __DIR__ . '/../core/Mailer.php';
			$mailer  = new Mailer($logger ?? null);
			$subject = 'Validar conta - SAW';
			$body    = "Olá {$nome},\n\nObrigado por se registar.\n\nO seu código de validação é: {$code}\n\nInsira-o na página de validação de conta para ativar a sua conta.\n\nSe não pediu registo, ignore este email.";
			$mailer->sendMail($email, $nome, $subject, $body);
		} catch(Exception $me){
			if(isset($logger) && method_exists($logger,'error')){
				$logger->error('Falha no envio de email de validação: '.$me->getMessage());
			}
		}

		$_SESSION['pending_user_id']    = $userId;
		$_SESSION['pending_user_email'] = $email;
		$_SESSION['flash_success']      = 'Conta criada. Verifique o seu email para validar a conta antes de iniciar sessão.';
		header('Location: /index.php?page=login'); exit;
	} catch(PDOException $e){
		@file_put_contents(__DIR__ . '/../private/logs/server_error.txt',
			'['.date('Y-m-d H:i:s').'] [REGISTER_ERROR]: '.$e->getMessage().PHP_EOL,
			FILE_APPEND|LOCK_EX
		);
		if(isset($logger) && method_exists($logger,'error')){
			$logger->error('Erro DB registo: '.$e->getMessage());
		}
		@unlink($targetPath);
		$_SESSION['flash_error'] = 'Erro no servidor. Tente novamente mais tarde.';
		header('Location: /index.php?page=register'); exit;
	}
}

// GET: mostrar formulário de registo ao utilizador
?>
<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8">
  <title>Registar - SAW</title>
  <link rel="stylesheet" href="/assets/css/style_public.css">
  <style>
    .auth-wrap{ max-width:520px; margin:36px auto; background:#fff; padding:20px; border-radius:10px; box-shadow:0 8px 24px rgba(2,6,23,0.06); }
    .auth-wrap h2{ margin:0 0 12px 0; }
    .form-row{ margin-bottom:12px; display:flex; flex-direction:column; gap:6px; }
    .form-row input, .form-row textarea{ padding:10px; border-radius:8px; border:1px solid #e6eef8; }
    .btn-login{ background:#0f5132; color:#fff; border:0; padding:10px 14px; border-radius:8px; cursor:pointer; width:100%; font-weight:600; }
    .msg{ margin-top:10px; font-size:0.95rem; }
	</style>
	<!-- JS de validações no lado do cliente (NIF, nome, password, etc.) -->
	<script src="/assets/js/validations.js" defer></script>
</head>
<body>
  <header class="topbar" role="navigation" aria-label="Navegação principal">
    <div class="logo">SAW — Sistema de Reservas</div>
    <nav class="nav" aria-label="Ações">
	  <!-- Usa o roteador central index.php?page=... para não expor a estrutura interna -->
	  <a class="ghost" href="/index.php?page=login">Login</a>
	  <a class="primary" href="/index.php?page=register">Registar</a>
    </nav>
  </header>

  <main class="container" role="main">
    <div class="auth-wrap" aria-live="polite">
      <h2>Registar Conta</h2>

      <?php if(!empty($_SESSION['flash_error'])): ?>
        <div class="msg" style="color:#9f1239;"><?php echo htmlspecialchars($_SESSION['flash_error']); unset($_SESSION['flash_error']); ?></div>
      <?php endif; ?>
      <?php if(!empty($_SESSION['flash_success'])): ?>
        <div class="msg" style="color:#065f46;"><?php echo htmlspecialchars($_SESSION['flash_success']); unset($_SESSION['flash_success']); ?></div>
      <?php endif; ?>

	  <!-- Formulário de registo (cliente-side validation em JS ajuda mas não substitui validação no servidor) -->
	  <form id="registerForm" method="post" action="/index.php?page=register" enctype="multipart/form-data">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
        <div class="form-row">
          <label>Nome completo *</label>
          <input type="text" name="nome" required>
        </div>
        <div class="form-row">
          <label>Email *</label>
          <input type="email" name="email" required>
        </div>
        <div class="form-row">
          <label>Senha *</label>
          <input type="password" name="password" required>
        </div>
        <div class="form-row">
          <label>Confirmar senha *</label>
          <input type="password" name="password_confirm" required>
        </div>
        <div class="form-row">
          <label>NIF (9 dígitos) *</label>
          <input type="text" name="nif" maxlength="9" required>
        </div>
        <div class="form-row">
          <label>Telemóvel *</label>
          <input type="text" name="telemovel" maxlength="15" required>
        </div>
        <div class="form-row">
          <label>Morada *</label>
          <input type="text" name="morada" required>
        </div>
        <div class="form-row">
          <label>Foto de Perfil (JPEG/PNG, máx 2MB) *</label>
          <input type="file" name="foto" accept="image/jpeg,image/png" required>
        </div>
        <div style="margin-top:8px;">
          <button class="btn-login" type="submit">Registar</button>
        </div>
      </form>
    </div>
  </main>

<script>
// Validação simples no cliente para ajudar o utilizador (não substitui a validação no servidor)
document.getElementById('registerForm').addEventListener('submit', function(e){
	var f    = e.target;
	var nome = f.nome.value.trim();
	var email= f.email.value.trim();
	var pass = f.password.value;
	var pass2= f.password_confirm.value;
	var nif  = f.nif.value;
	var tel  = f.telemovel.value;
	var addr = f.morada.value;
	var fotoInput = f.foto;
	var file = (fotoInput && fotoInput.files && fotoInput.files[0]) ? fotoInput.files[0] : null;

	var msg = '';
	if(!validateName(nome)) msg = 'Nome inválido. Indique o nome completo.';
	else if(!validateEmailFormat(email)) msg = 'Email inválido.';
	else if(!validatePasswordStrong(pass)) msg = 'Senha fraca. Deve ter pelo menos 10 caracteres, incluindo maiúsculas, minúsculas, números e símbolos.';
	else if(pass !== pass2) msg = 'As senhas não coincidem.';
	else if(!validateNIF(nif)) msg = 'NIF inválido (deve ter 9 dígitos válidos).';
	else if(!validatePhone(tel)) msg = 'Telemóvel inválido.';
	else if(!validateAddress(addr)) msg = 'Morada inválida.';
	else {
	var imgCheck = validateProfileImageClient(file);
	if(!imgCheck.ok) msg = imgCheck.msg || 'Imagem inválida.';
	}

	if(msg){
	e.preventDefault();
	alert(msg);
	}
});
</script>
</body>
</html>