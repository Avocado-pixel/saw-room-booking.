<?php

/**
 * Classe Auth: centraliza operações relacionadas com autenticação.
 *
 * Responsável por:
 * - Autenticar utilizadores por email/password.
 * - Gerir o token "remember me" (cookie + coluna token_remember na BD).
 * - Efetuar login automático a partir da cookie remember_me.
 */
class Auth {
	/** @var PDO */
	private $pdo;
	/** @var Logger */
	private $logger;
	/**
	 * Chave da aplicação (APP_KEY). Atualmente não é usada diretamente aqui,
	 * mas fica disponível para possíveis evoluções (ex.: tokens assinados).
	 */
	private $key;

	public function __construct(PDO $pdo, Logger $logger, $appKey){
		$this->pdo = $pdo;
		$this->logger = $logger;
		$this->key = $appKey;
	}

	/**
	 * Autentica um utilizador por email e password.
	 *
	 * Devolve o array de utilizador (inclui perfil, estado e twofa_secret)
	 * se a password for válida, ou false em caso contrário.
	 */
	public function authenticate($email, $password){
		// Traz tudo o que o login precisa: perfil, estado e twofa_secret
		$stmt = $this->pdo->prepare('
			SELECT id,nome,email,password,perfil,estado,twofa_secret
			  FROM utilizadores
			 WHERE email = :e
			 LIMIT 1
		');
		$stmt->execute([':e'=>$email]);
		$user = $stmt->fetch();
		// Verifica a password usando password_verify(), função nativa do PHP que
		// lê o hash gerado por password_hash() (inclui automaticamente o salt) e
		// compara de forma segura com a palavra-passe introduzida.
		if($user && password_verify($password, $user['password'])){
			return $user;
		}
		return false;
	}

	/**
	 * "Remember me" baseado em token aleatório guardado na BD (token_remember).
	 *
	 * Cria um token forte, grava o hash na BD e coloca o token simples
	 * numa cookie segura (httponly). O prazo padrão é 30 dias.
	 */
	public function setRememberCookie($userId, $days = 30){
		$userId = (int)$userId;
		if($userId <= 0) return;

		// gera token aleatório para remember
		try {
			$rawToken = bin2hex(random_bytes(32)); // valor que irá para a cookie
		} catch(Exception $e){
			$rawToken = sha1($userId.microtime(true).mt_rand());
		}

		// hash para guardar na BD (sequestra o valor real em caso de fuga de BD)
		$hash = hash('sha256', $rawToken);

		// Expiração do token remember (aqui só usada na cookie; se quiseres
		// podes também guardar a data de expiração na BD)
		$expUnix = time() + ($days * 86400);

		// grava hash na BD
		$stmt = $this->pdo->prepare("UPDATE utilizadores SET token_remember = :t WHERE id = :id");
		$stmt->execute([':t'=>$hash, ':id'=>$userId]);

		// coloca token simples na cookie
		$isSecure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
		setcookie(
			'remember_me',
			$rawToken,
			$expUnix,
			'/',
			'',
			$isSecure,
			true
		);
	}

	/**
	 * Limpa a cookie remember_me no browser e o token_remember na BD
	 * para o utilizador atualmente autenticado.
	 */
	public function clearRememberCookie(){
		$isSecure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

		// limpar cookie no browser
		setcookie('remember_me', '', time() - 3600, '/', '', $isSecure, true);

		// limpar token na BD para o utilizador atual (se existir)
		if(isset($_SESSION) && !empty($_SESSION['user_id'])){
			$st = $this->pdo->prepare("UPDATE utilizadores SET token_remember = NULL WHERE id = :id");
			$st->execute([':id' => (int)$_SESSION['user_id']]);
		}
	}

	/**
	 * Login automático via cookie remember_me + token_remember na BD.
	 *
	 * Se a cookie corresponder a um utilizador com conta disponível,
	 * cria a sessão com user_id/perfil/email e regista auditoria.
	 */
	public function loginFromRememberCookie(){
		if(!isset($_COOKIE['remember_me']) || $_COOKIE['remember_me'] === '') return false;

		$rawToken = $_COOKIE['remember_me'];
		// token simples; fazemos hash e comparamos com a BD
		$hash = hash('sha256', $rawToken);

		// procurar utilizador com esse token e conta disponível
		$sql = "SELECT id,nome,email,perfil FROM utilizadores
		        WHERE token_remember = :t AND estado = 'disponivel'
		        LIMIT 1";
		$st = $this->pdo->prepare($sql);
		$st->execute([':t'=>$hash]);
		$user = $st->fetch(PDO::FETCH_ASSOC);
		if(!$user) return false;

		// Criar sessão (se ainda não existir)
		if(!isset($_SESSION)) session_start();
		$_SESSION['user_id'] = $user['id'];
		$_SESSION['perfil']  = $user['perfil'];
		$_SESSION['email']   = $user['email'] ?? null;
		// Define também o momento de expiração da sessão (20 minutos por omissão).
		// Esta informação é usada em index.php para fazer logout automático
		// quando o tempo de sessão é excedido.
		$_SESSION['login_expires_at'] = time() + (20 * 60);

		// Gerar token de sessão exclusivo para forçar sessão única por utilizador
		$sessionToken = null;
		try {
			$sessionToken = bin2hex(random_bytes(32));
		} catch (Exception $e) {
			$sessionToken = bin2hex(random_bytes(16));
		}
		try {
			$stTok = $this->pdo->prepare("UPDATE utilizadores SET current_session_token = :t WHERE id = :id");
			$stTok->execute([':t'=>$sessionToken, ':id'=>$user['id']]);
			$_SESSION['session_token'] = $sessionToken;
		} catch (PDOException $e) {
			if(isset($this->logger)) $this->logger->error('SESSION_TOKEN_UPDATE_REMEMBER: '.$e->getMessage());
		}

		if(isset($this->logger)){
			$this->logger->audit_user($user['id'], 'LOGIN_REMEMBER', 'Login automático via token_remember');
		}

		return true;
	}
}