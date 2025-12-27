<?php
/**
 * index.php — ponto de entrada principal e roteador da aplicação.
 *
 * Responsável por:
 *   - carregar o bootstrap (ligações à BD, logs, segurança, etc.);
 *   - expor funções helper para verificar sessão, expiração e permissões;
 *   - despachar pedidos com base em dois parâmetros principais:
 *       - action: usado para operações (login, logout, ações admin, etc.);
 *       - page:   usado para escolher que página mostrar (públicas, user_, admin_);
 *   - encaminhar pedidos para os ficheiros certos em routes/, cliente/,
 *     administracao/ ou public/ de forma organizada;
 *   - devolver uma página 404 amigável quando não encontra uma rota válida.
 *
 * Do ponto de vista de segurança, este ficheiro é o "porteiro":
 *   - impede acesso a páginas admin_ se o utilizador não tiver perfil admin;
 *   - garante que páginas user_ só são acedidas por utilizadores autenticados;
 *   - regista acessos admin negados no Logger.
 */

// Carrega o bootstrap (ambiente de aplicação)
require_once __DIR__ . '/bootstrap.php';
// pequenos helpers de proteção (ver abaixo)

/**
 * Verifica se a sessão autenticada expirou.
 *
 * Se existir user_id em sessão e o campo login_expires_at já tiver passado,
 * limpa a sessão, tenta remover a cookie remember_me e redireciona para o login.
 *
 * Nota: o campo login_expires_at é definido em:
 * - routes/auth.php (no momento do login com ou sem 2FA)
 * - core/Auth.php::loginFromRememberCookie() (login automático por cookie)
 * - routes/auth.php (ação renew_session via AJAX)
 */
/**
 * Verifica se a sessão autenticada expirou por inatividade.
 *
 * - Se não existir utilizador em sessão, não faz nada.
 * - Se existir e o campo login_expires_at já tiver passado, a sessão é
 *   terminada e o utilizador é redirecionado para o login com uma mensagem
 *   amigável.
 * - Também tenta apagar a cookie "remember_me" através de Auth.
 */
function check_session_timeout(){
	if(empty($_SESSION['user_id'])) return;

	$now = time();

	// Verificar se o token de sessão na BD coincide com o da sessão atual
	if(isset($GLOBALS['pdo'])){
		try {
			$st = $GLOBALS['pdo']->prepare("SELECT current_session_token FROM utilizadores WHERE id = :id LIMIT 1");
			$st->execute([':id' => (int)$_SESSION['user_id']]);
			$row     = $st->fetch(PDO::FETCH_ASSOC);
			$dbToken = $row['current_session_token'] ?? null;
			$sessTok = $_SESSION['session_token'] ?? null;

			// Migração suave: se existir token na BD mas ainda não na sessão, copia para sessão
			if($dbToken && !$sessTok){
				$_SESSION['session_token'] = $dbToken;
			}
			// Se existir na sessão mas não na BD, sincroniza na BD
			elseif($sessTok && !$dbToken){
				$up = $GLOBALS['pdo']->prepare("UPDATE utilizadores SET current_session_token = :t WHERE id = :id");
				$up->execute([':t'=>$sessTok, ':id'=>(int)$_SESSION['user_id']]);
			}
			// Se ambos existirem e forem diferentes, existe outra sessão mais recente → terminar esta
			elseif($dbToken && $sessTok && $dbToken !== $sessTok){
				if(isset($GLOBALS['logger'])){
					$GLOBALS['logger']->audit_user($_SESSION['user_id'], 'SESSION_CONCURRENT', 'Sessão terminada devido a novo login noutro dispositivo.');
				}
				// tentar remover cookie remember_me
				if(isset($GLOBALS['auth']) && $GLOBALS['auth']){
					try { $GLOBALS['auth']->clearRememberCookie(); } catch (Throwable $e) { /* silencioso */ }
				}
				// limpar sessão e redirecionar para login
				$_SESSION = [];
				if(session_status() === PHP_SESSION_ACTIVE){
					session_destroy();
				}
				$next = urlencode($_SERVER['REQUEST_URI'] ?? '/');
				header('Location: /index.php?page=login&next=' . $next);
				exit;
			}
		} catch (Throwable $e){
			// Em caso de erro ao verificar token de sessão, não bloquear o utilizador;
			// o controlo de inatividade continua a ser aplicado abaixo.
		}
	}
	// Se não existir ainda login_expires_at, define agora (migração suave)
	if(empty($_SESSION['login_expires_at'])){
		$_SESSION['login_expires_at'] = $now + (20 * 60);
		return;
	}
	if($_SESSION['login_expires_at'] > $now) return;

	// Sessão expirada → registar e terminar sessão
	if(isset($GLOBALS['logger']) && isset($_SESSION['user_id'])){
		$GLOBALS['logger']->audit_user($_SESSION['user_id'], 'SESSION_EXPIRED', 'Sessão expirada por inatividade (20 min).');
	}
	// Tentar remover cookie remember_me se existir Auth global
	if(isset($GLOBALS['auth']) && $GLOBALS['auth']){
		try { $GLOBALS['auth']->clearRememberCookie(); } catch (Throwable $e) { /* falha silenciosa */ }
	}
	// Limpar sessão em memória
	$_SESSION = [];
	if(session_status() === PHP_SESSION_ACTIVE){
		session_destroy();
	}
	$next = urlencode($_SERVER['REQUEST_URI'] ?? '/');
	header('Location: /index.php?page=login&next=' . $next);
	exit;
}

/**
 * Garante que o utilizador está autenticado para aceder a certas páginas.
 *
 * Se não houver utilizador em sessão, redireciona para a página de login,
 * guardando na query string a página que o utilizador queria ver para que
 * possa voltar automaticamente após login bem sucedido.
 */
function require_auth(){
	check_session_timeout();
	if(empty($_SESSION['user_id'])){
		$next = urlencode($_SERVER['REQUEST_URI'] ?? '/');
		header('Location: /index.php?page=login&next=' . $next);
		exit;
	}
}
/**
 * Garante que o utilizador é administrador.
 *
 * - Verifica sessão e expiração;
 * - Se o perfil não for 'admin', devolve HTTP 403 e regista o evento em
 *   Logger::error("Acesso admin negado.").
 */
function require_admin(){
	check_session_timeout();
	if(empty($_SESSION['user_id']) || ($_SESSION['perfil'] ?? '') !== 'admin'){
		http_response_code(403);
		// registar tentativa
		if(isset($GLOBALS['logger'])) $GLOBALS['logger']->error('Acesso admin negado.');
		exit('Acesso negado.');
	}
}

$action = $_REQUEST['action'] ?? null;
// página por omissão: salas públicas
$page = $_GET['page'] ?? 'public_rooms'; // default

// --- NOVO: servir foto de utilizador (armazenada em private/uploads) ---
if($action === 'user_photo'){
	// só permitir se houver sessão
	if(empty($_SESSION['user_id'])){
		http_response_code(403); exit;
	}
	$uidReq = (int)($_GET['uid'] ?? 0);
	// permitir ver apenas a própria foto ou, se for admin, qualquer uma
	$isAdmin = (($_SESSION['perfil'] ?? '') === 'admin');
	if($uidReq <= 0 || (!$isAdmin && $uidReq !== (int)$_SESSION['user_id'])){
		http_response_code(403); exit;
	}

	// ler caminho da foto da BD
	$stmt = $pdo->prepare("SELECT foto FROM utilizadores WHERE id = :id LIMIT 1");
	$stmt->execute([':id' => $uidReq]);
	$row = $stmt->fetch(PDO::FETCH_ASSOC);
	if(!$row || empty($row['foto'])){
		http_response_code(404); exit;
	}

	// construir caminho físico: ex.: "private/uploads/xxxx.jpg"
	$rel = ltrim($row['foto'], '/');
	$path = __DIR__ . '/' . $rel;
	if(!is_file($path)){
		http_response_code(404); exit;
	}

	// detectar mime-type e enviar ficheiro
	$finfo = new finfo(FILEINFO_MIME_TYPE);
	$mime = $finfo->file($path) ?: 'application/octet-stream';
	header('Content-Type: '.$mime);
	header('Content-Length: '.filesize($path));
	// evitar qualquer output anterior
	readfile($path);
	exit;
}

// Normalizações / aliases: permitir "forgot" apontar para recuperar_senha_pedir
if($page === 'forgot') {
	$page = 'recuperar_senha_pedir';
}
// compatibilidade com antigo "recuperar_senha"
if($page === 'recuperar_senha'){
	$page = 'recuperar_senha_pedir';
}
// NOVO: mapear nomes antigos de páginas de recuperação
// para os novos nomes em /public (pedir_reset, reset_password)
if($page === 'recuperar_senha_pedir'){
	$page = 'pedir_reset';
}
if($page === 'recuperar_senha_reset'){
	$page = 'reset_password';
}

// lista de ações cliente protegidas (via /index.php?action=...)
// atualmente só é usada para profile_update (atualizar perfil do utilizador)
$clientProtectedActions = ['profile_update'];

// lista de ações auth manejadas por routes/auth.php
// (atualmente apenas login/logout/renew_session)
$authActions = ['login','logout','renew_session'];

// 1) ACTION handling
if($action){
	// 1a) handler específico em routes/
	$file = __DIR__ . '/routes/' . $action . '.php';
	if(file_exists($file)){ require $file; exit; }

	// 1b) ações de autenticação (login/logout/renew)
	if(in_array($action, $authActions, true)){
		$file = __DIR__ . '/routes/auth.php';
		if(file_exists($file)){ require $file; exit; }
	}

	// 1c) ações cliente protegidas -> require_auth then include client handler
	if(in_array($action, $clientProtectedActions, true)){
		require_auth();
		$file = __DIR__ . '/cliente/' . $action . '.php';
		if(file_exists($file)){ require $file; exit; }
		http_response_code(404); echo 'Ação de cliente não encontrada.'; exit;
	}

	// 1e) ações admin (prefixo admin_)
	if(strpos($action, 'admin_') === 0){
		// exigir admin
		require_admin();

		// priorizar rota específica em administracao/
		$fileAdminSpecific = __DIR__ . '/administracao/' . $action . '.php';
		if(file_exists($fileAdminSpecific)){ require $fileAdminSpecific; exit; }

		// NOVO: ações admin de utilizadores (estado, perfil)
		$crudUserActions = ['admin_set_user_estado','admin_set_user_perfil'];
		$fileAdminUsers = __DIR__ . '/administracao/admin_users.php';
		if(in_array($action, $crudUserActions, true) && file_exists($fileAdminUsers)){
			require $fileAdminUsers;
			exit;
		}

		// fallback: se exista administracao/admin_rooms.php e a ação for uma das operações CRUD simples
		$crudActions = ['admin_add_room','admin_edit_room','admin_delete_room'];
		$fileAdminRooms = __DIR__ . '/administracao/admin_rooms.php';
		if(in_array($action, $crudActions, true) && file_exists($fileAdminRooms)){
			require $fileAdminRooms;
			exit;
		}

		// caso não exista handler específico
		http_response_code(404);
		require __DIR__ . '/404.php';
		exit;
	}

	// Não encontrado
	http_response_code(404);
	require __DIR__ . '/404.php';
	exit;
}

// 2) PAGE handling
// 2a) páginas admin_ -> proteger e incluir administracao/<page>.php se existir
if(strpos($page, 'admin_') === 0){
	require_admin();
	$file = __DIR__ . '/administracao/' . $page . '.php';
	if(file_exists($file)){ require $file; exit; }
	http_response_code(404);
	require __DIR__ . '/404.php';
	exit;
}

// 2b) páginas user_ -> proteger e incluir cliente/<page>.php
if(strpos($page, 'user_') === 0){
	require_auth();
	$file = __DIR__ . '/cliente/' . $page . '.php';
	if(file_exists($file)){ require $file; exit; }
	http_response_code(404);
	require __DIR__ . '/404.php';
	exit;
}

// 2c) páginas públicas em public/
$fileCandidates = [
	__DIR__ . '/public/' . $page . '.php',
];
foreach($fileCandidates as $p){
	if(file_exists($p)){ require $p; exit; }
}

// 3) fallback público -> se nada encontrado, 404 bonito
http_response_code(404);
require __DIR__ . '/404.php';
exit;