<?php
/**
 * Configuração da base de dados e inicialização mínima do esquema.
 *
 * Responsabilidades deste ficheiro:
 * - Definir constantes de ligação (host, nome da BD, utilizador, password).
 * - Garantir a existência da pasta privada (private/) e da pasta de logs.
 * - Gerir a APP_KEY (chave secreta) a partir de variável de ambiente ou ficheiro
 *   privado (private/app_key.txt), gerando uma nova se não existir.
 * - Criar a ligação PDO ($pdo) com opções seguras (erro por exceção, utf8mb4).
 * - Se a base de dados ainda não existir, criá-la e gerar o esquema mínimo:
 *     - Tabela utilizadores (contas de utilizador e respetivos tokens);
 *     - Tabela salas (salas de reunião/uso);
 *     - Tabela reservas (ligando utilizadores a salas).
 *
 * Notas de segurança/importantes:
 * - Este ficheiro contém credenciais de acesso à base de dados; deve ser protegido
 *   e nunca exposto publicamente ou comitado em repositórios públicos.
 * - APP_KEY é usada noutros pontos do sistema para gerar HMACs (hashes de códigos
 *   de validação, recuperação de password, etc.), pelo que deve ser mantida secreta.
 */

// Configuração da base de dados e rotina de inicialização do esquema
// Apenas DB aqui — SMTP e outras configurações foram removidas deste ficheiro.

define('DB_HOST','localhost');
define('DB_NAME','saw');
define('DB_USER','example');
define('DB_PASS','example'); 

// Garantir existência de directório privado (logs e keys)
$privateDir = __DIR__ . '/../private/';
$logDir = $privateDir . 'logs/';
if(!is_dir($privateDir)){
	@mkdir($privateDir, 0770, true);
}
if(!is_dir($logDir)){
	@mkdir($logDir, 0770, true);
	@file_put_contents($logDir . '.htaccess', "Deny from all\n");
}

// APP_KEY: usar variável de ambiente, ficheiro privado ou gerar e persistir
if(!defined('APP_KEY')){
	$appKeyEnv = getenv('APP_KEY');
	if($appKeyEnv && strlen($appKeyEnv) >= 16){
		define('APP_KEY', $appKeyEnv);
	} else {
		$keyFile = $privateDir . 'app_key.txt';
		if(file_exists($keyFile) && is_readable($keyFile)){
			$key = null;
			$lines = @file($keyFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			if($lines !== false){
				foreach($lines as $line){
					$line = trim($line);
					if($line === '' || strpos($line, '#') === 0) continue;
					$key = $line;
					break;
				}
			} else {
				$key = trim(@file_get_contents($keyFile));
			}
			if(!empty($key)) define('APP_KEY', $key);
		}
		if(!defined('APP_KEY')){
			try {
				$key = bin2hex(random_bytes(32));
			} catch (Exception $ex){
				// fallback seguro
				$key = hash('sha256', DB_PASS . uniqid('', true));
			}
			@file_put_contents($keyFile, $key);
			@chmod($keyFile, 0600);
			define('APP_KEY', $key);
		}
	}
}

// Ficheiro de log de erros de base de dados (partilha o mesmo conceito de server_error)
$errorServerFile = $logDir . 'server_error.txt';

// Helper de logging (privado, sem exposição ao cliente)
$log_private = function($tag, $msg) use ($errorServerFile) {
	$ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
	$line = '['.date('Y-m-d H:i:s').'] ['.$ip.'] [--] ['.$tag.']: '.$msg.PHP_EOL;
	@file_put_contents($errorServerFile, $line, FILE_APPEND|LOCK_EX);
};

// Configuração PDO e tentativa de ligação
$dsn = 'mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4';
$options = [
	PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
	PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
	PDO::ATTR_EMULATE_PREPARES => false,
];

try {
	$pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
} catch (PDOException $e){
	$errMsg = $e->getMessage();
	$errCode = $e->getCode();

	// Se a BD não existe -> tentar criar e assegurar esquema
	$unknownDb = (strpos($errMsg, 'Unknown database') !== false) || ($errCode == 1049);
	if($unknownDb){
		try {
			$dsnNoDb = 'mysql:host='.DB_HOST.';charset=utf8mb4';
			$pdoTemp = new PDO($dsnNoDb, DB_USER, DB_PASS, $options);
			$createSql = "CREATE DATABASE IF NOT EXISTS `".DB_NAME."` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;";
			$pdoTemp->exec($createSql);

			// Re-conectar à BD recém-criada
			$pdo = new PDO($dsn, DB_USER, DB_PASS, $options);

			// Assegurar esquema: criar tabelas se não existirem
			$schemaStatements = [
				// UTILIZADORES
				"CREATE TABLE IF NOT EXISTS `utilizadores` (
					`id` INT AUTO_INCREMENT PRIMARY KEY,
					`nome` VARCHAR(191) NOT NULL,
					`email` VARCHAR(191) NOT NULL UNIQUE,
					`password` VARCHAR(255) NOT NULL,
					`nif` VARCHAR(20) NOT NULL UNIQUE,
					`telemovel` VARCHAR(20) NOT NULL,
					`morada` VARCHAR(255) NOT NULL,
					`foto` VARCHAR(255) NOT NULL,
					`perfil` ENUM('admin','utente') NOT NULL DEFAULT 'utente',
					`estado` ENUM('pendente','disponivel','bloqueado','eliminado') NOT NULL DEFAULT 'pendente',
					`token_recuperacao` VARCHAR(255),
					`token_recuperacao_expira` DATETIME,
					`token_remember` VARCHAR(255),
					`token_validacao_email` VARCHAR(255),
					`token_validacao_email_expira` DATETIME,
					`twofa_secret` VARCHAR(255) NULL,
					`current_session_token` VARCHAR(255) NULL
				) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
				// SALAS
				"CREATE TABLE IF NOT EXISTS `salas` (
					`id` INT AUTO_INCREMENT PRIMARY KEY,
					`nome` VARCHAR(191) NOT NULL,
					`capacidade` INT NOT NULL DEFAULT 1,
					`estado` ENUM('disponivel','indisponivel','brevemente') NOT NULL DEFAULT 'disponivel',
					`foto` VARCHAR(255) NOT NULL,
					`estado_registo` ENUM('disponivel','bloqueado','eliminado') NOT NULL DEFAULT 'disponivel'
				) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
				// RESERVAS
				"CREATE TABLE IF NOT EXISTS `reservas` (
					`id` INT AUTO_INCREMENT PRIMARY KEY,
					`user_id` INT NOT NULL,
					`sala_id` INT NOT NULL,
					`data_inicio` DATETIME NOT NULL,
					`data_fim` DATETIME NOT NULL,
					`token_partilha` VARCHAR(255),
					CONSTRAINT `fk_reservas_user` FOREIGN KEY (`user_id`) REFERENCES `utilizadores`(`id`) ON DELETE CASCADE,
					CONSTRAINT `fk_reservas_sala` FOREIGN KEY (`sala_id`) REFERENCES `salas`(`id`) ON DELETE CASCADE
				) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
			];

			// Correr as instruções de schema
			foreach ($schemaStatements as $sql) {
				try {
					$pdo->exec($sql);
				} catch (PDOException $e) {
					@file_put_contents(__DIR__ . '/../private/logs/error.db.schema.txt',
						'['.date('Y-m-d H:i:s').'] [DB_SCHEMA] '.$e->getMessage()." SQL: ".$sql.PHP_EOL,
						FILE_APPEND | LOCK_EX
					);
				}
			}

			unset($pdoTemp);
		} catch (PDOException $e2){
			$log_private('DB_ERROR_CREATE', $e2->getMessage());
			exit('Ocorreu um erro inesperado. Por favor tente novamente mais tarde.');
		}
	} else {
		$log_private('DB_ERROR', $e->getMessage());
		exit('Ocorreu um erro inesperado. Por favor tente novamente mais tarde.');
	}
}

// Seed muito simples: 3 utilizadores (1 admin + 2 utentes) e 9 salas
// Só corre se as tabelas estiverem vazias. Evita scripts externos.
try {
	// --- UTILIZADORES ---
	$hasUsersStmt = $pdo->query("SELECT COUNT(*) FROM utilizadores");
	$hasUsers = (int)$hasUsersStmt->fetchColumn();
	if($hasUsers === 0){
		$defaultPassword = 'Str0ngP@ssw0rd!'; // forte: maiúsculas, minúsculas, dígitos e símbolo
		$hash = password_hash($defaultPassword, PASSWORD_BCRYPT);
		$fotoDefault = 'private/uploads/perfis/perfilvazio.jpg';

		$users = [
			[
				'nome'      => 'Admin Sistema',
				'email'     => 'example1@example.com',
				'nif'       => '123456789', // NIF válido
				'telemovel' => '911111111',
				'morada'    => 'Morada Admin',
				'perfil'    => 'admin',
			],
			[
				'nome'      => 'Utilizador Demo 1',
				'email'     => 'example2@example.com',
				'nif'       => '234567899', // NIF válido
				'telemovel' => '922222222',
				'morada'    => 'Morada Demo 1',
				'perfil'    => 'utente',
			],
			[
				'nome'      => 'Utilizador Demo 2',
				'email'     => 'example3@example.com',
				'nif'       => '345678907', // NIF válido
				'telemovel' => '933333333',
				'morada'    => 'Morada Demo 2',
				'perfil'    => 'utente',
			],
		];

		$insUser = $pdo->prepare("INSERT INTO utilizadores (nome,email,password,nif,telemovel,morada,foto,perfil,estado) VALUES (:nome,:email,:pass,:nif,:tel,:morada,:foto,:perfil,'disponivel')");
		foreach($users as $u){
			try {
				$insUser->execute([
					':nome'   => $u['nome'],
					':email'  => $u['email'],
					':pass'   => $hash,
					':nif'    => $u['nif'],
					':tel'    => $u['telemovel'],
					':morada' => $u['morada'],
					':foto'   => $fotoDefault,
					':perfil' => $u['perfil'],
				]);
			} catch (PDOException $e){
				$log_private('DB_SEED_USER', $e->getMessage());
			}
		}
	}

	// --- SALAS ---
	$hasRoomsStmt = $pdo->query("SELECT COUNT(*) FROM salas");
	$hasRooms = (int)$hasRoomsStmt->fetchColumn();
	if($hasRooms === 0){
		$rooms = [
			['nome' => 'Sala 1', 'capacidade' => 8,  'estado' => 'disponivel', 'foto' => 'private/uploads/rooms/1765462098_80adba531a74.jpg'],
			['nome' => 'Sala 2', 'capacidade' => 10, 'estado' => 'disponivel', 'foto' => 'private/uploads/rooms/1765462122_6dd8e94186d5.jpg'],
			['nome' => 'Sala 3', 'capacidade' => 12, 'estado' => 'disponivel', 'foto' => 'private/uploads/rooms/1765462131_f292dbdc0bc4.jpg'],
			['nome' => 'Sala 4', 'capacidade' => 15, 'estado' => 'disponivel', 'foto' => 'private/uploads/rooms/1765462138_59c0ecee9d41.jpg'],
			['nome' => 'Sala 5', 'capacidade' => 20, 'estado' => 'disponivel', 'foto' => 'private/uploads/rooms/1765462145_8038be9844e6.jpg'],
			['nome' => 'Sala 6', 'capacidade' => 25, 'estado' => 'disponivel', 'foto' => 'private/uploads/rooms/1765462157_99c868f0fb2e.jpg'],
			['nome' => 'Sala 7', 'capacidade' => 6,  'estado' => 'disponivel', 'foto' => 'private/uploads/rooms/1765641880_9fed1101b2f2.jpg'],
			['nome' => 'Sala 8', 'capacidade' => 14, 'estado' => 'disponivel', 'foto' => 'private/uploads/rooms/1765641889_b950674ea865.jpg'],
			['nome' => 'Sala 9', 'capacidade' => 30, 'estado' => 'disponivel', 'foto' => 'private/uploads/rooms/1765641901_c9ad1778b550.jpg'],
		];

		$insSala = $pdo->prepare("INSERT INTO salas (nome,capacidade,estado,foto,estado_registo) VALUES (:nome,:capacidade,:estado,:foto,'disponivel')");
		foreach($rooms as $r){
			try {
				$insSala->execute([
					':nome'       => $r['nome'],
					':capacidade' => $r['capacidade'],
					':estado'     => $r['estado'],
					':foto'       => $r['foto'],
				]);
			} catch (PDOException $e){
				$log_private('DB_SEED_SALA', $e->getMessage());
			}
		}
	}
} catch (PDOException $e){
	$log_private('DB_SEED', $e->getMessage());
}

// Fim: configuração da base de dados.
// Observação: toda a configuração relacionada com envio de email (SMTP) foi removida deste ficheiro deliberadamente.
// Se necessário, crie um ficheiro separado em private/ (ex.: private/app_config.php) para configurações extras.