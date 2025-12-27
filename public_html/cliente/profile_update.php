<?php
/**
 * Ação profile_update: atualizações de perfil do utilizador.
 *
 * Este ficheiro não é acedido diretamente por URL como página; é chamado
 * através do router central com:
 *   /index.php?action=profile_update
 *
 * É responsável por três tipos de operações, diferenciadas pelo campo
 * "stage" vindo em POST:
 *   - send_code: validar novos dados de perfil (nome/email/telemóvel/morada
 *     e foto), guardar temporariamente na sessão e enviar um código de 6
 *     dígitos por email para confirmação;
 *   - confirm_update: confirmar o código de 6 dígitos e aplicar as
 *     alterações em segurança na base de dados, incluindo a foto de perfil;
 *   - set_password: alterar a password do utilizador (verificando a atual
 *     e validando a nova password como "forte").
 *
 * Segurança:
 *   - só é executado para utilizadores autenticados (router faz require_auth);
 *   - cada pedido POST requer um token CSRF válido;
 *   - todos os campos são limpos / validados via Validator;
 *   - os códigos de confirmação são guardados como hash HMAC com APP_KEY
 *     e têm tempo limite;
 *   - a alteração de password usa password_hash/password_verify;
 *   - é feita auditoria em Logger (PROFILE_UPDATED, PASSWORD_CHANGED).
 */

// Garante sessão ativa para ler dados do utilizador e flash messages
if(!isset($_SESSION)) session_start();
if(empty($_SESSION['user_id'])) {
	http_response_code(403);
	$_SESSION['flash_error'] = 'Autenticação necessária.';
	header('Location: /index.php?page=login');
	exit;
}
if(!isset($pdo)) require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../core/security.php';

// NÃO vamos devolver JSON para o cliente; usamos apenas flash + redirect
$post  = Security::clean_array($_POST);
$stage = $post['stage'] ?? '';

// CSRF
if(!Security::verify_csrf($post['csrf'] ?? '')) {
	$_SESSION['flash_error'] = 'Sessão inválida. Tente novamente.';
	header('Location: /index.php?page=user_profile');
	exit;
}

$uid = (int)$_SESSION['user_id'];

// 1) Enviar código para confirmar alterações de perfil (nome/telemóvel/morada/foto/email)
if($stage === 'send_code'){
	// sanitizar campos como no register.php
	$nome      = \Validator::sanitizeNome($post['nome'] ?? '');
	$email     = \Validator::sanitizeEmail($post['email'] ?? '');
	$telemovel = \Validator::sanitizeTelemovel($post['telemovel'] ?? '');
	$morada    = \Validator::sanitizeMorada($post['morada'] ?? '');

	// validações
	if($nome === '' || !\Validator::validateName($nome)){
		$_SESSION['flash_error'] = 'Nome inválido. Indique o nome completo.'; 
		header('Location: /index.php?page=user_profile'); exit;
	}
	if($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)){
		$_SESSION['flash_error'] = 'Email inválido.'; 
		header('Location: /index.php?page=user_profile'); exit;
	}
	// email não pode estar em uso por outro utilizador
	$chk = $pdo->prepare("SELECT id FROM utilizadores WHERE email = :e AND id != :id LIMIT 1");
	$chk->execute([':e'=>$email, ':id'=>$uid]);
	if($chk->fetch()){
		$_SESSION['flash_error'] = 'Este email já está associado a outra conta.'; 
		header('Location: /index.php?page=user_profile'); exit;
	}

	if($morada === ''){
		$_SESSION['flash_error'] = 'Morada inválida.'; 
		header('Location: /index.php?page=user_profile'); exit;
	}
	if($telemovel !== '' && strlen($telemovel) < 9){
		$_SESSION['flash_error'] = 'Telemóvel inválido.'; 
		header('Location: /index.php?page=user_profile'); exit;
	}

	// validar foto (opcional) com os mesmos parâmetros do register.php
	$imgCheck = \Validator::validateProfileImage($_FILES['foto'] ?? null, false);
	if(!$imgCheck['ok']){
		$_SESSION['flash_error'] = $imgCheck['error'] ?? 'Imagem inválida.';
		header('Location: /index.php?page=user_profile'); exit;
	}
	$ext = $imgCheck['ext'];

	// processar foto temporária se enviada
	$tempFile = null;
	if(!empty($_FILES['foto']) && $_FILES['foto']['error'] === UPLOAD_ERR_OK && $ext){
		$foto = $_FILES['foto'];
		$dir = __DIR__ . '/../private/temp_uploads/';
		if(!is_dir($dir)) @mkdir($dir, 0770, true);
		$basename = time() . '_' . bin2hex(random_bytes(6)) . '.' . $ext;
		$dest = $dir . $basename;
		if(!move_uploaded_file($foto['tmp_name'], $dest)){
			$_SESSION['flash_error'] = 'Falha ao guardar imagem.';
			header('Location: /index.php?page=user_profile'); exit;
		}
		$tempFile = 'private/temp_uploads/' . $basename;
	}

	// guardar só o que foi pedido para alterar
	$_SESSION['pending_profile_change'] = [
		'nome'      => $nome,
		'email'     => $email,
		'telemovel' => $telemovel,
		'morada'    => $morada,
		'foto'      => $tempFile,
		'created'   => time()
	];

	$code = random_int(100000, 999999);
	$_SESSION['profile_change_code_hash']   = hash_hmac('sha256',(string)$code, APP_KEY);
	$_SESSION['profile_change_code_expire'] = time() + 15*60;

	$st = $pdo->prepare("SELECT email,nome FROM utilizadores WHERE id = :id LIMIT 1");
	$st->execute([':id'=>$uid]); $u = $st->fetch(PDO::FETCH_ASSOC);
	if(!$u){
		$_SESSION['flash_error'] = 'Utilizador não encontrado.';
		header('Location: /index.php?page=user_profile'); exit;
	}

	// AJUSTE: usar o mesmo padrão que em register.php
	try {
		require_once __DIR__ . '/../core/Mailer.php';
		$mailer  = new Mailer($logger ?? null);
		$subject = 'Confirmar alteração de perfil - SAW';
		$body    = "Olá {$u['nome']},\n\nO seu código para confirmar alterações de perfil é: {$code}\nÉ válido por 15 minutos.\n\nSe não pediu esta alteração, ignore este email.";
		$mailer->sendMail($u['email'], $u['nome'], $subject, $body);
	} catch(Exception $me){
		if(isset($logger) && method_exists($logger,'error')){
			$logger->error('Falha no envio de email de alteração de perfil: '.$me->getMessage());
		}
	}

	$_SESSION['flash_success'] = 'Enviámos um código para o seu email. Introduza-o no campo indicado.';
	header('Location: /index.php?page=user_profile'); exit;
}

// 2) Confirmar código e aplicar alterações de perfil (confirm_update)
if($stage === 'confirm_update'){
	$code = $post['code'] ?? '';
	if(!preg_match('/^\d{6}$/', $code)){
		$_SESSION['flash_error'] = 'Código inválido.';
		header('Location: /index.php?page=user_profile'); exit;
	}

	$hash   = $_SESSION['profile_change_code_hash']   ?? '';
	$expire = $_SESSION['profile_change_code_expire'] ?? 0;

	if($hash === '' || $expire < time()){
		$_SESSION['flash_error'] = 'Código expirado. Peça novo código.';
		header('Location: /index.php?page=user_profile'); exit;
	}
	if(!hash_equals($hash, hash_hmac('sha256',(string)$code, APP_KEY))){
		$_SESSION['flash_error'] = 'Código incorreto.';
		header('Location: /index.php?page=user_profile'); exit;
	}

	$pending = $_SESSION['pending_profile_change'] ?? null;
	if(!$pending){
		$_SESSION['flash_error'] = 'Não existem alterações pendentes.';
		header('Location: /index.php?page=user_profile'); exit;
	}

	try {
		$pdo->beginTransaction();

		$nome      = $pending['nome'];
		$email     = $pending['email'];
		$telemovel = $pending['telemovel'];
		$morada    = $pending['morada'];
		$fotoPath  = null;

		if(!empty($pending['foto'])){
			$src = __DIR__ . '/../' . $pending['foto'];
			if(file_exists($src)){
				$ext = pathinfo($src, PATHINFO_EXTENSION);
				$destName = bin2hex(random_bytes(16)).'.'.$ext;
				// Guardar foto final em private/uploads/perfis/
				$destRel  = 'private/uploads/perfis/' . $destName;
				$dest     = __DIR__ . '/../' . $destRel;
				rename($src, $dest);
				@chmod($dest, 0640);
				$fotoPath = $destRel;
			}
		}

		$sql = "UPDATE utilizadores SET nome = :n, email = :e, telemovel = :t, morada = :m";
		$params = [
			':n'=>$nome,
			':e'=>$email,
			':t'=>$telemovel,
			':m'=>$morada,
			':id'=>$uid
		];
		if($fotoPath){
			$sql .= ", foto = :f";
			$params[':f'] = $fotoPath;
		}
		$sql .= " WHERE id = :id";

		$upd = $pdo->prepare($sql);
		$upd->execute($params);
		$pdo->commit();

		unset($_SESSION['pending_profile_change'], $_SESSION['profile_change_code_hash'], $_SESSION['profile_change_code_expire']);

		// NOVO: logar atualização de perfil
		if(isset($logger) && method_exists($logger,'audit_user')){
			$logger->audit_user($uid,'PROFILE_UPDATED','Dados de perfil atualizados (nome/email/telemóvel/morada/foto)');
		}

		$_SESSION['flash_success'] = 'Perfil atualizado com sucesso.';
		header('Location: /index.php?page=user_profile'); exit;
	} catch(Exception $e){
		$pdo->rollBack();
		$_SESSION['flash_error'] = 'Erro a atualizar o perfil.';
		header('Location: /index.php?page=user_profile'); exit;
	}
}

// 3) Alterar password (senha atual + nova)
if($stage === 'set_password'){
	$passCurrent = $post['current_password'] ?? '';
	$pass        = $post['password'] ?? '';
	$passc       = $post['password_confirm'] ?? '';

	if($pass === '' || $pass !== $passc || !\Validator::validatePasswordStrong($pass)){
		$_SESSION['flash_error'] = 'Senha inválida. Deve ter pelo menos 10 caracteres, incluindo maiúsculas, minúsculas, números e símbolos.'; 
		header('Location: /index.php?page=user_profile'); exit;
	}

	$st = $pdo->prepare("SELECT password FROM utilizadores WHERE id = :id LIMIT 1");
	$st->execute([':id'=>$uid]); $row = $st->fetch(PDO::FETCH_ASSOC);
	// Verificação segura da password atual.
	// password_verify() é a função nativa do PHP que sabe ler o formato
	// gerado por password_hash() (inclui o salt automático) e comparar
	// a palavra-passe introduzida com o hash guardado.
	if(!$row || !password_verify($passCurrent, $row['password'])){
		$_SESSION['flash_error'] = 'Senha atual incorreta.'; 
		header('Location: /index.php?page=user_profile'); exit;
	}

	// Novo hash da password com salt automático gerido pelo PHP.
	$hash = password_hash($pass, PASSWORD_BCRYPT);
	try {
		$upd = $pdo->prepare("UPDATE utilizadores SET password = :p WHERE id = :id");
		$upd->execute([':p'=>$hash, ':id'=>$uid]);

		// NOVO: logar alteração de password
		if(isset($logger) && method_exists($logger,'audit_user')){
			$logger->audit_user($uid,'PASSWORD_CHANGED','Password alterada no perfil do utilizador');
		}

		$_SESSION['flash_success'] = 'Senha alterada com sucesso.';
		header('Location: /index.php?page=user_profile'); exit;
	} catch(Exception $e){
		$_SESSION['flash_error'] = 'Erro no servidor ao alterar senha.';
		header('Location: /index.php?page=user_profile'); exit;
	}
}

// stage desconhecido
$_SESSION['flash_error'] = 'Ação inválida.';
header('Location: /index.php?page=user_profile');
exit;
