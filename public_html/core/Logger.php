<?php
// Classe simples de logging/auditoria para o sistema SAW.
// Regista erros gerais e eventos importantes de utilizadores, reservas e salas em ficheiros de texto.
class Logger {
	private $dir;

	public function __construct($dir){
		// Diretório base onde os ficheiros de log vão ser guardados
		$this->dir = rtrim($dir, '/') . '/';

		// Garante que o diretório existe (cria se for necessário)
		if(!is_dir($this->dir)){
			mkdir($this->dir, 0770, true);
		}

		// Cria um .htaccess para proteger os logs de acesso direto via HTTP
		// (aceita apenas acesso via ficheiro, não pelo browser)
		@file_put_contents(dirname($this->dir).'/'.'.htaccess', "Deny from all\n");
	}

	// Método interno genérico para escrever uma linha de log num ficheiro.
	private function write($file, $userId, $action, $details){
		$ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
		$line = '['.date('Y-m-d H:i:s').'] ['.$ip.'] ['.($userId ?? '--').'] ['.$action.']: '.$details.PHP_EOL;
		@file_put_contents($this->dir.$file, $line, FILE_APPEND|LOCK_EX);
	}

	/**
	 * Regista um erro genérico da aplicação (lógica de negócio, falhas de email, etc.).
	 *
	 * Estes erros vão para o ficheiro errors.txt dentro do diretório privado de logs
	 * (por exemplo, private/logs/errors.txt) e não são mostrados ao utilizador.
	 * Os erros técnicos de PHP/servidor são registados separadamente em
	 * server_error.txt pelo bootstrap.
	 *
	 * Ex.: $logger->error('Falha ao enviar email', $userIdOpcional);
	 */
	public function error($message, $userId = null){
		$this->write('errors.txt', $userId, 'ERROR', $message);
	}

	/**
	 * Auditoria de ações de utilizador (conta, login, 2FA, perfil, etc.).
	 * O ID do utilizador é sempre incluído na linha de log.
	 * Ex.: $logger->audit_user($id,'LOGIN','Login efetuado');
	 */
	public function audit_user($userId, $action, $details){
		$this->write('audit_users.txt', $userId, $action, $details);
	}

	/**
	 * Auditoria de reservas de salas feitas por clientes.
	 * Ficheiro: reserva_salas.txt
	 * Ex.: $logger->audit_reserva($userId,'RESERVA_CRIADA',"Sala 3 de 2025-01-01 10:00 a 11:00");
	 */
	public function audit_reserva($userId, $action, $details){
		$this->write('reserva_salas.txt', $userId, $action, $details);
	}

	/**
	 * Auditoria de ações de administração relacionadas com utilizadores.
	 * Ficheiro: admin_users.txt
	 * Ex.: $logger->audit_admin_user($adminId,'VIEW_USER_RESERVAS','Admin X viu reservas do utilizador Y');
	 */
	public function audit_admin_user($adminId, $action, $details){
		$this->write('admin_users.txt', $adminId, $action, $details);
	}

	/**
	 * Auditoria de consultas de reservas feitas pela administração.
	 * Ficheiro: admin_reservas.txt
	 * Ex.: $logger->audit_admin_reservas($adminId,'VIEW_DAILY_RESERVAS','Admin X consultou reservas do dia 2025-01-01');
	 */
	public function audit_admin_reservas($adminId, $action, $details){
		$this->write('admin_reservas.txt', $adminId, $action, $details);
	}

	/**
	 * Auditoria de ações de administração sobre salas (criar/editar/apagar sala).
	 * Ficheiro: salas_admin.txt
	 * Ex.: $logger->audit_sala_admin($adminId,'SALA_CRIADA','Sala 5 criada');
	 */
	public function audit_sala_admin($userId, $action, $details){
		$this->write('salas_admin.txt', $userId, $action, $details);
	}

	/**
	 * Auditoria: pedido de código de recuperação de senha.
	 */
	public function audit_recovery_request(int $userId, string $email): void {
		$details = "Utilizador {$userId} pediu código de recuperação para {$email}";
		$this->audit_user($userId, 'RECOVERY_REQUEST', $details);
	}

	/**
	 * Auditoria: conclusão da recuperação de senha (password alterada com código válido).
	 */
	public function audit_recovery_complete(int $userId, string $email): void {
		$details = "Utilizador {$userId} alterou a password via recuperação para {$email}";
		$this->audit_user($userId, 'RECOVERY_COMPLETE', $details);
	}

	// ...existing code (se houver mais métodos)...
}