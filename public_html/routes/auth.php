<?php
/**
 * Rota/handler central de autenticação.
 *
 * Integração com o router principal (index.php):
 * - Este ficheiro é incluído quando o parâmetro `action` da query ou POST
 *   está relacionado com autenticação, por exemplo:
 *     - index.php?action=login
 *     - index.php?action=logout
 *     - index.php?action=renew_session
 *
 * Ações suportadas:
 * - renew_session (AJAX): chamada periódica por JavaScript para manter a sessão ativa,
 *   regenerando o ID de sessão e prolongando o timeout, protegida por CSRF.
 * - login (AJAX): recebe credenciais, valida estado de conta e, se necessário, aplica
 *   um segundo passo com 2FA (Two-Factor Authentication) via TwoFAHelper.
 * - logout (GET): termina sessão, remove cookies de sessão e remember_me e redireciona
 *   o utilizador para a listagem pública de salas.
 *
 * Segurança e auditoria:
 * - Todos os pedidos AJAX validam CSRF usando Security::verify_csrf().
 * - Palavra-passe e remember_me são tratados via classe Auth, que centraliza a lógica.
 * - Movimentos importantes (LOGIN, LOGIN_2FA, LOGIN_REMEMBER, LOGOUT, SESSION_RENEW)
 *   são registados em Logger::audit_user() para permitir auditoria posterior.
 */

// Rota/handler central de autenticação.
//
// Este ficheiro é incluído a partir de index.php quando é passado
// um parâmetro `action` relacionado com autenticação, por exemplo:
//   index.php?action=login
//   index.php?action=logout
//   index.php?action=renew_session
//
// Aqui são tratados exclusivamente 3 tipos de ações:
// - renew_session (AJAX)
// - login         (AJAX)
// - logout        (pedido normal por GET)

// Garante que a sessão está iniciada
if(!isset($_SESSION)) session_start();
// Funções de segurança (limpeza inputs e CSRF)
require_once __DIR__ . '/../core/security.php';

// Variáveis globais esperadas: $pdo (PDO), $auth (classe Auth), $logger (registo/auditoria).
// A ação pode vir por POST (AJAX) ou por GET (links normais).
$action = $_POST['action'] ?? $_GET['action'] ?? null;

// ----------------------
// 1) Renovar sessão (AJAX) — action=renew_session
// ----------------------
// Usado por assets/js/session_manager.js para manter a sessão ativa
// enquanto o utilizador tem a página aberta, sem obrigar a novo login.
//
// Quando chamada com sucesso, além de regenerar o ID de sessão, renova
// também o tempo de expiração da sessão (20 minutos).
if($action === 'renew_session'){
	// Verifica token CSRF antes de renovar a sessão
	if(!Security::verify_csrf($_POST['csrf'] ?? '')){
		http_response_code(400);
		echo json_encode(['ok'=>false,'msg'=>'token inválido']);
		exit;
	}
	if(isset($_SESSION['user_id'])){
		// Gera novo ID de sessão para reduzir risco de fixação de sessão
		session_regenerate_id(true);
		// Renova o timeout da sessão para mais 20 minutos
		$_SESSION['login_expires_at'] = time() + (20 * 60);
		// Regista auditoria da renovação
		$logger->audit_user($_SESSION['user_id'], 'SESSION_RENEW', 'Sessão renovada via AJAX');
		echo json_encode(['ok'=>true,'msg'=>'sessão renovada']);
		exit;
	}
	// Caso não haja utilizador autenticado
	echo json_encode(['ok'=>false,'msg'=>'não autenticado']);
	exit;
}

// ----------------------
// 2) Login (AJAX) — action=login
// ----------------------
// Usado pela view views/login.php, que envia o formulário via fetch/JSON
// para index.php?action=login.
//
// O fluxo suporta 2 passos quando há 2FA ativo:
//   - PASSO 1: validar email + password e estado da conta.
//   - PASSO 2: validar apenas o código 2FA.
if($action === 'login'){
	header('Content-Type: application/json');

	$input = Security::clean_array($_POST);

	if(!Security::verify_csrf($input['csrf'] ?? '')){
		echo json_encode(['ok'=>false,'msg'=>'CSRF inválido']); exit;
	}

	// Indica em que passo do fluxo 2FA estamos: '' ou 'verify'
	$twofaStep = $input['twofa_step'] ?? '';

	// -----------------------------
	// PASSO 2: verificar apenas o código 2FA
	// -----------------------------
	if($twofaStep === 'verify'){
		$code2fa = trim($input['twofa_code'] ?? '');
		if(!preg_match('/^\d{6}$/', $code2fa)){
			echo json_encode(['ok'=>false,'msg'=>'Código 2FA inválido.','code'=>'2FA_INVALID']); exit;
		}
		if(empty($_SESSION['2fa_user_id'])){
			echo json_encode(['ok'=>false,'msg'=>'Sessão 2FA expirada. Faça login novamente.','code'=>'2FA_EXPIRED']); exit;
		}
		$userId2fa = (int)$_SESSION['2fa_user_id'];

		try{
			$st = $pdo->prepare("SELECT id,perfil,estado,twofa_secret FROM utilizadores WHERE id = :id LIMIT 1");
			$st->execute([':id'=>$userId2fa]);
			$userRow = $st->fetch(PDO::FETCH_ASSOC);
		} catch(PDOException $e){
			if(isset($logger)) $logger->error('2FA verify: erro DB '.$e->getMessage());
			echo json_encode(['ok'=>false,'msg'=>'Erro interno.']); exit;
		}

		if(!$userRow){
			echo json_encode(['ok'=>false,'msg'=>'Utilizador não encontrado.','code'=>'2FA_EXPIRED']); exit;
		}
		if(($userRow['estado'] ?? 'pendente') !== 'disponivel'){
			echo json_encode(['ok'=>false,'msg'=>'Conta não se encontra ativa.','code'=>'ACCOUNT_INACTIVE']); exit;
		}
		if(empty($userRow['twofa_secret'])){
			echo json_encode(['ok'=>false,'msg'=>'2FA não está ativo nesta conta.','code'=>'2FA_NOT_ENABLED']); exit;
		}

		// Carrega helper de 2FA baseado na biblioteca RobThree/Auth
		require_once __DIR__ . '/../core/twofactorauth';
		if(!TwoFAHelper::verifyCode($userRow['twofa_secret'], $code2fa, 'SAW')){
			echo json_encode(['ok'=>false,'msg'=>'Código 2FA inválido.','code'=>'2FA_INVALID']); exit;
		}

		// Código 2FA válido → cria sessão normal
		$_SESSION['user_id'] = $userRow['id'];
		$_SESSION['perfil']  = $userRow['perfil'] ?? 'utente';
		// Timeout de sessão: 20 minutos a partir deste momento
		$_SESSION['login_expires_at'] = time() + (20 * 60);

		// Gerar token de sessão exclusivo para forçar sessão única por utilizador
		$sessionToken = null;
		try {
			$sessionToken = bin2hex(random_bytes(32));
		} catch (Exception $e) {
			$sessionToken = bin2hex(random_bytes(16));
		}
		try {
			$stTok = $pdo->prepare("UPDATE utilizadores SET current_session_token = :t WHERE id = :id");
			$stTok->execute([':t'=>$sessionToken, ':id'=>$userRow['id']]);
			$_SESSION['session_token'] = $sessionToken;
		} catch (PDOException $e) {
			if(isset($logger)) $logger->error('SESSION_TOKEN_UPDATE_2FA: '.$e->getMessage());
		}

		if(isset($logger) && method_exists($logger,'audit_user')){
			$logger->audit_user($userRow['id'],'LOGIN_2FA','Login efetuado com 2FA');
		}

		// aplicar remember-me se tiver ficado pendente
		if(!empty($_SESSION['2fa_remember'])){
			$auth->setRememberCookie($userRow['id']);
		}

		unset($_SESSION['2fa_user_id'], $_SESSION['2fa_remember']);

		// AJUSTE: devolver também perfil
		echo json_encode([
			'ok'     => true,
			'msg'    => 'autenticado',
			'perfil' => $userRow['perfil'] ?? 'utente'
		]);
		exit;
	}

	// -----------------------------
	// PASSO 1: login email + password
	// -----------------------------
	$email    = $input['email'] ?? '';
	$password = $input['password'] ?? '';
	$remember = !empty($input['remember']);

	// authenticate já devolve perfil, estado e twofa_secret (ver classe Auth)
	$user = $auth->authenticate($email, $password);

	if($user){
		// --- verificar estado da conta antes de permitir login ---
		$estado = $user['estado'] ?? 'pendente';

		if($estado === 'pendente'){
			echo json_encode([
				'ok'   => false,
				'msg'  => 'A sua conta ainda não foi validada. Por favor valide o email.',
				'code' => 'PENDING',
				// Redireciona via roteador central, mantendo a estrutura interna escondida
				'redirect' => '/index.php?page=validar_conta',
				'email' => $email
			]); exit;
		}
		if($estado === 'bloqueado'){
			echo json_encode(['ok'=>false,'msg'=>'A sua conta foi bloqueada. Contacte o administrador.','code'=>'BLOCKED']); exit;
		}
		if($estado === 'eliminado'){
			if(isset($logger)) $logger->error('Login em conta eliminada para ' . $email);
			echo json_encode(['ok'=>false,'msg'=>'Credenciais inválidas']); exit;
		}
		if($estado !== 'disponivel'){
			echo json_encode(['ok'=>false,'msg'=>'Conta não se encontra ativa.']); exit;
		}

		// Se tiver 2FA ativo → não faz login já, pede código no 2.º passo
		$twofaSecret = $user['twofa_secret'] ?? null;
		if(!empty($twofaSecret)){
			$_SESSION['2fa_user_id']  = $user['id'];
			$_SESSION['2fa_remember'] = $remember ? 1 : 0;
			echo json_encode([
				'ok'        => true,
				'needs_2fa' => true,
				'msg'       => '2FA requerido'
			]);
			exit;
		}

		// Sem 2FA → login normal
		$_SESSION['user_id'] = $user['id'];
		$_SESSION['perfil']  = $user['perfil'];
		// Timeout de sessão: 20 minutos a partir do login
		$_SESSION['login_expires_at'] = time() + (20 * 60);

		// Gerar token de sessão exclusivo para forçar sessão única por utilizador
		$sessionToken = null;
		try {
			$sessionToken = bin2hex(random_bytes(32));
		} catch (Exception $e) {
			$sessionToken = bin2hex(random_bytes(16));
		}
		try {
			$stTok = $pdo->prepare("UPDATE utilizadores SET current_session_token = :t WHERE id = :id");
			$stTok->execute([':t'=>$sessionToken, ':id'=>$user['id']]);
			$_SESSION['session_token'] = $sessionToken;
		} catch (PDOException $e) {
			if(isset($logger)) $logger->error('SESSION_TOKEN_UPDATE_LOGIN: '.$e->getMessage());
		}

		if(isset($logger) && method_exists($logger,'audit_user')){
			$logger->audit_user($user['id'],'LOGIN','Login efetuado (sem 2FA)');
		}
		if($remember) $auth->setRememberCookie($user['id']);

		echo json_encode([
			'ok'     => true,
			'msg'    => 'autenticado',
			'perfil' => $user['perfil']
		]);
	} else {
		if(isset($logger)) $logger->error('Login falhou para ' . $email);
		echo json_encode(['ok'=>false,'msg'=>'Credenciais inválidas']);
	}
	exit;
}

// ----------------------
// 3) Logout — action=logout
// ----------------------
// Chamado a partir de vários links/botões (layouts Admin/Client, JS, etc.).
// Remove cookies de sessão/"lembrar sessão", destrói a sessão e redireciona
// para a listagem pública de salas.
if($action === 'logout'){
	if(isset($_SESSION['user_id']) && isset($logger) && method_exists($logger,'audit_user')){
		$logger->audit_user($_SESSION['user_id'],'LOGOUT','Logout do utilizador');
	}

	// Pede à classe Auth que remova qualquer cookie de "lembrar sessão"
	$auth->clearRememberCookie();

	// Limpa todos os dados da sessão
	$_SESSION = [];
	// Remove cookie de sessão do browser, se existir
	if (ini_get("session.use_cookies")) {
		$params = session_get_cookie_params();
		setcookie(session_name(), '', time() - 42000,
			$params["path"], $params["domain"],
			$params["secure"], $params["httponly"]
		);
	}
	// Destrói a sessão no servidor
	session_destroy();

	// Redireciona para a página pública de salas
	header('Location: /index.php?page=public_rooms');
	exit;
}

// ----------------------
// 4) Ação desconhecida
// ----------------------
http_response_code(400);
echo 'Ação inválida.';
exit;
