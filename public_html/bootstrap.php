<?php
/**
 * Bootstrap da aplicação.
 *
 * Este ficheiro é incluído logo no início (por exemplo em index.php) e é o
 * responsável por preparar todo o ambiente da aplicação:
 *   - configura o PHP para não mostrar erros técnicos ao utilizador final;
 *   - regista um autoloader simples para classes dentro de core/;
 *   - inicia a sessão com opções mais seguras (cookies httpOnly, SameSite, etc.);
 *   - configura o fuso horário;
 *   - garante a existência de uma pasta privada para logs e cria um .htaccess
 *     a bloquear o acesso direto a esses ficheiros;
 *   - regista handlers globais de erros e exceções para escrever em
 *     private/logs/server_error.txt;
 *   - carrega a configuração de base de dados e cria o objeto PDO;
 *   - instancia objetos centrais como Logger, Validator e Auth;
 *   - tenta um login automático por cookie ("remember me") caso não exista
 *     sessão;
 *   - prepara um token CSRF global e expõe variáveis úteis via $GLOBALS.
 */

ini_set('display_errors', '0');
error_reporting(E_ALL);

// Autoload
spl_autoload_register(function($class){
	$paths = [
		__DIR__ . '/core/' . $class . '.php',
	];
	foreach($paths as $p) if(file_exists($p)) include $p;
});

// Sessão
if(session_status() === PHP_SESSION_NONE){
	// session_set_cookie_params array suportado em versões recentes; fallback simples se necessário
	if (version_compare(PHP_VERSION, '7.3.0', '>=')) {
		session_start([
			'cookie_httponly' => true,
			'cookie_samesite' => 'Lax',
			'cookie_secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'
		]);
	} else {
		@ini_set('session.cookie_httponly', 1);
		session_start();
	}
}

// Garantir timezone (evita warnings)
@date_default_timezone_set(@date_default_timezone_get() ?: 'Europe/Lisbon');

// Garantir private e logs
$privateDir = __DIR__ . '/private';
$logDir = $privateDir . '/logs';
if(!is_dir($privateDir)) @mkdir($privateDir, 0770, true);
if(!is_dir($logDir)) @mkdir($logDir, 0770, true);
@file_put_contents($logDir . '/.htaccess', "Deny from all\n");

// Ficheiro de log privado principal (erros técnicos do servidor / PHP)
// Apenas aqui são registados erros de baixo nível; o utilizador vê
// apenas uma mensagem genérica e amigável.
$serverLogFile = $logDir . '/server_error.txt';

// Handler de logging privado (sem saída para o utilizador)
$writeServerLog = function($level, $msg, $file = '-', $line = '-') use ($serverLogFile) {
	$ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
	$lineMsg = '['.date('Y-m-d H:i:s').'] ['.$ip.'] [--] ['.$level.']: '.$msg.' in '.$file.':'.$line.PHP_EOL;
	@file_put_contents($serverLogFile, $lineMsg, FILE_APPEND|LOCK_EX);
};

// Registar handlers (silenciosos ao utilizador)
set_error_handler(function($errno, $errstr, $errfile, $errline) use ($writeServerLog){
	// Regista o erro técnico e impede que o PHP o mostre ao utilizador
	$writeServerLog('ERROR', $errstr, $errfile, $errline);
	return true;
});
set_exception_handler(function($e) use ($writeServerLog){
	$writeServerLog('EXCEPTION', $e->getMessage(), $e->getFile(), $e->getLine());
	http_response_code(500);
	// Mensagem genérica para o utilizador; detalhe apenas no server_error.txt
	exit('Ocorreu um erro inesperado. Por favor tente novamente mais tarde.');
});
register_shutdown_function(function() use ($writeServerLog){
	$err = error_get_last();
	if($err && in_array($err['type'], [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_PARSE], true)){
		$writeServerLog('FATAL', $err['message'], $err['file'], $err['line']);
		// Em caso de erro fatal, garantir que o utilizador não vê mensagens técnicas
		if(!headers_sent()){
			http_response_code(500);
		}
		// Tentar limpar qualquer saída parcial
		while(ob_get_level() > 0){ @ob_end_clean(); }
		echo 'Ocorreu um erro inesperado. Por favor tente novamente mais tarde.';
	}
});

// Carregar config (cria $pdo e APP_KEY)
require_once __DIR__ . '/config/db.php';

// Garantir Security class disponível (se existir no core)
if(file_exists(__DIR__ . '/core/security.php')) require_once __DIR__ . '/core/security.php';

// Instanciar cores (Logger/Validator/Auth devem existir em core/ e ser carregáveis via autoload)
$logger = null;
$validator = null;
$auth = null;

if(class_exists('Logger')) {
	$logger = new Logger($logDir . '/');
}
if(class_exists('Validator')) {
	$validator = new Validator();
}
if(!defined('APP_KEY') || APP_KEY === ''){
	$writeServerLog('CONFIG_ERROR','APP_KEY ausente', __FILE__, __LINE__);
	exit('Ocorreu um erro inesperado. Por favor tente novamente mais tarde.');
}
if(class_exists('Auth')) {
	// aqui o Auth é criado com $pdo, $logger e APP_KEY
	$auth = new Auth($pdo ?? null, $logger, APP_KEY);
}

// NOVO: tentar login automático via cookie remember_me se ainda não houver sessão
if(empty($_SESSION['user_id'])){
	// isto chama Auth::loginFromRememberCookie(), que:
	// 1) lê a cookie remember_me,
	// 2) procura o utilizador com esse token (token_remember) na BD,
	// 3) se encontrar, define $_SESSION['user_id'], $_SESSION['perfil'], $_SESSION['email']
	$auth->loginFromRememberCookie();
}

// CSRF token pronto
$csrf = null;
if(class_exists('Security') && method_exists('Security', 'csrf_token')){
	$csrf = \Security::csrf_token();
}

// Exportar variáveis úteis para o resto da aplicação via $GLOBALS
$GLOBALS['pdo'] = $pdo ?? ($GLOBALS['pdo'] ?? null);
$GLOBALS['logger'] = $logger ?? ($GLOBALS['logger'] ?? null);
$GLOBALS['validator'] = $validator ?? ($GLOBALS['validator'] ?? null);
$GLOBALS['auth'] = $auth ?? ($GLOBALS['auth'] ?? null);
$GLOBALS['csrf'] = $csrf ?? ($GLOBALS['csrf'] ?? null);

// Função de render com injeção automática do CSS público
/**
 * Renderiza um ficheiro de view (PHP/HTML) garantindo que o CSS público
 * principal é incluído, caso a view ainda não o tenha.
 *
 * Esta função assume que o ficheiro de view foi pensado para ser incluído
 * diretamente (sem layout de admin/cliente) e injeta um <link> para o CSS
 * público se não detectar nenhuma referência a esse ficheiro no HTML gerado.
 *
 * @param string $viewPath         Caminho absoluto para o ficheiro da view.
 * @param string $publicCssRelative Caminho relativo para o CSS público a inserir.
 */
function render_view_with_public_css(string $viewPath, string $publicCssRelative = 'assets/css/style_public.css'){
	// se a view não existir, responder 404 em vez de tentar incluir
	if(!file_exists($viewPath)){
		http_response_code(404);
		echo "Página não encontrada.";
		return;
	}

	ob_start();
	// disponibiliza algumas variáveis à view (a view herda o escopo desta função)
	$pdo = $GLOBALS['pdo'] ?? null;
	$csrf = $GLOBALS['csrf'] ?? null;
	$logger = $GLOBALS['logger'] ?? null;
	$auth = $GLOBALS['auth'] ?? null;
	include $viewPath;
	$out = ob_get_clean();

	// se a view devolve JSON, apenas imprimimos
	$trim = ltrim($out);
	if(strlen($trim) > 0 && ($trim[0] === '{' || $trim[0] === '[')) {
		echo $out; return;
	}

	// inserir link para CSS público se a view não o declarar
	$variants = [$publicCssRelative, '/' . ltrim($publicCssRelative, '/')];
	$found = false;
	foreach($variants as $v) if(stripos($out, $v) !== false){ $found = true; break; }

	if(!$found){
		$link = "\n<link rel=\"stylesheet\" href=\"/" . ltrim($publicCssRelative, '/') . "\">\n";
		if(preg_match('/<head[^>]*>/i', $out, $m, PREG_OFFSET_CAPTURE)){
			$pos = $m[0][1] + strlen($m[0][0]);
			$out = substr_replace($out, $link, $pos, 0);
		} else {
			$out = $link . $out;
		}
	}
	echo $out;
}
