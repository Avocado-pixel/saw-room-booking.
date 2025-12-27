<?php
// Mailer simples e legível com suporte opcional a SMTP e fila em caso de falha.
// Carrega a configuração de config/mailer_config.php e usa PHPMailer se estiver disponível.

/**
 * Classe responsável pelo envio de emails da aplicação.
 *
 * Suporta:
 * - Envio via SMTP através de PHPMailer (se configurado).
 * - Fila de emails em ficheiros JSON quando o envio por SMTP falha (opcional).
 * - Fallback para a função nativa mail() quando o SMTP não está configurado.
 */
class Mailer {
	/**
	 * Endereço de email utilizado no campo "From" por omissão.
	 */
	private $from = 'example@gmail.com';

	/**
	 * Instância de logger externo ,
	 * usada para registar erros além do ficheiro de logs interno.
	 */
	private $logger;

	/**
	 * Array com configurações de SMTP (host, porta, utilizador, etc.).
	 */
	private $smtp = [];

	/**
	 * Indica se o envio via SMTP está ativo.
	 */
	private $use_smtp = false;

	/**
	 * Construtor do Mailer.
	 *
	 * Lê a configuração em config/mailer_config.php, normaliza as chaves de
	 * configuração e aplica valores por defeito, podendo ainda receber
	 * sobreposições (overrides) através do parâmetro $overrides.
	 */
	public function __construct($logger = null, array $overrides = []){
		$this->logger = $logger;
		// Carrega config apenas de config/mailer_config.php
		$file = __DIR__ . '/../config/mailer_config.php';
		$cfg = (file_exists($file) && is_readable($file)) ? (array) @include $file : [];

		// normalize keys we care about
		$map = [
			'host'=>'smtp_host','port'=>'smtp_port','user'=>'smtp_user','username'=>'smtp_user',
			'pass'=>'smtp_pass','password'=>'smtp_pass','secure'=>'smtp_secure','from'=>'from',
			'auth_type'=>'smtp_auth_type','timeout'=>'smtp_timeout','debug'=>'smtp_debug',
			'queue_on_fail'=>'smtp_queue_on_fail'
		];
		$norm = [];
		foreach($cfg as $k=>$v){
			$lk = strtolower($k);
			$norm[$map[$lk] ?? $lk] = $v;
		}

		$defaults = [
			'smtp_host'=>'smtp.gmail.com',
			'smtp_port'=>587,
			'smtp_user'=>null,
			'smtp_pass'=>null,
			'smtp_secure'=>'tls',
			'smtp_auth_type'=>'LOGIN',
			'smtp_timeout'=>30,
			'smtp_debug'=>false,
			'smtp_queue_on_fail'=>false,
			'from'=>$this->from,
		];

		$this->smtp = array_merge($defaults, $norm, $overrides);
		// Atualiza o endereço "from" caso venha na configuração
		$this->from = $this->smtp['from'] ?? $this->from;
		// Ativa o uso de SMTP apenas se existir utilizador e password
		$this->use_smtp = !empty($this->smtp['smtp_user']) && !empty($this->smtp['smtp_pass']);
	}

	/**
	 * Logger privado mínimo: escreve para a pasta private/logs.
	 *
	 * Cada linha contém data/hora, IP (ou "cli" em linha de comandos),
	 * uma tag identificadora e a mensagem.
	 */
	private function log($tag, $msg){
		$dir = __DIR__ . '/../private/logs/';
		if(!is_dir($dir)) @mkdir($dir, 0770, true);
		$line = '['.date('Y-m-d H:i:s').'] ['.($_SERVER['REMOTE_ADDR'] ?? 'cli').'] ['.$tag.'] '.$msg.PHP_EOL;
		@file_put_contents($dir . 'server_error.txt', $line, FILE_APPEND|LOCK_EX);
		// Se existir logger externo com método error(), também regista lá
		if($this->logger && method_exists($this->logger,'error')) $this->logger->error("[$tag] $msg");
	}

	/**
	 * Limpa e normaliza um endereço de email.
	 *
	 * Remove espaços e aplica FILTER_SANITIZE_EMAIL para garantir um formato válido.
	 */
	private function sanitizeEmail(string $s): string {
		return filter_var(trim($s), FILTER_SANITIZE_EMAIL);
	}

	/**
	 * Fila simples de emails: guarda um ficheiro JSON com os dados do email
	 * para ser enviado mais tarde por um processo externo (cron/job).
	 */
	private function queue_email(string $to, string $name, string $subject, string $body, array $meta = []): bool {
		$dir = __DIR__ . '/../private/mail_queue/';
		if(!is_dir($dir)) @mkdir($dir, 0770, true);
		// Registo base com data ISO, destinatário, assunto, corpo e metadata adicional
		$rec = ['at'=>date('c'),'to'=>$to,'name'=>$name,'subject'=>$subject,'body'=>$body,'meta'=>$meta];
		// Nome do ficheiro inclui timestamp + random para evitar colisões
		$file = $dir . time() . '_' . bin2hex(random_bytes(6)) . '.json';
		$ok = @file_put_contents($file, json_encode($rec, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT));
		if($ok) { $this->log('MAILER_QUEUE',"Queued mail to $to -> $file"); return true; }
		$this->log('MAILER_QUEUE_ERR',"Failed to write queue file for $to");
		return false;
	}

	/**
	 * Método principal para envio de emails genéricos.
	 *
	 * 1) Valida o email do destinatário.
	 * 2) Se o SMTP estiver configurado, tenta enviar via PHPMailer.
	 * 3) Se o SMTP não estiver ativo, faz fallback para mail() nativo.
	 */
	public function sendMail(string $toEmail, string $toName, string $subject, string $body){
		// Normaliza e valida o email de destino
		$to = $this->sanitizeEmail($toEmail);
		if(!filter_var($to, FILTER_VALIDATE_EMAIL)) return false;

		// Se o SMTP estiver configurado, tenta usar PHPMailer
		if($this->use_smtp){
			// --- tentar carregar PHPMailer automaticamente (via composer ou versão local) ---
			if(!class_exists('\\PHPMailer\\PHPMailer\\PHPMailer')){
				$vendor = __DIR__ . '/../vendor/autoload.php';
				if(file_exists($vendor)) {
					@include_once $vendor;
				}
			}
			// Se ainda não existir a classe, tenta carregar a partir de core/PHPMailer/
			if(!class_exists('\\PHPMailer\\PHPMailer\\PHPMailer')){
				$possible = [
					__DIR__ . '/PHPMailer/src/Exception.php',
					__DIR__ . '/PHPMailer/src/PHPMailer.php',
					__DIR__ . '/PHPMailer/src/SMTP.php',
				];
				$allExist = true;
				foreach($possible as $p) if(!file_exists($p)) { $allExist = false; break; }
				if($allExist){
					require_once __DIR__ . '/PHPMailer/src/Exception.php';
					require_once __DIR__ . '/PHPMailer/src/PHPMailer.php';
					require_once __DIR__ . '/PHPMailer/src/SMTP.php';
				}
			}
			// --- fim do autoload manual do PHPMailer ---

			if(class_exists('\\PHPMailer\\PHPMailer\\PHPMailer')){
				try {
					$mail = new \PHPMailer\PHPMailer\PHPMailer(true);
					$mail->isSMTP();
					$mail->Host = $this->smtp['smtp_host'];
					$mail->Port = (int)$this->smtp['smtp_port'];
					$mail->SMTPAutoTLS = true;
					$mail->Timeout = (int)$this->smtp['smtp_timeout'];
					$mail->SMTPAuth = true;
					$mail->Username = $this->smtp['smtp_user'];
					$mail->Password = $this->smtp['smtp_pass'];
					// Define cifragem (tls/ssl) se configurado
					if(!empty($this->smtp['smtp_secure'])) $mail->SMTPSecure = $this->smtp['smtp_secure'];
					// Define tipo de autenticação (por defeito LOGIN)
					if(!empty($this->smtp['smtp_auth_type'])) $mail->AuthType = $this->smtp['smtp_auth_type'];
					// Força UTF-8 no SMTP/PHPMailer para evitar problemas com acentos
					$mail->CharSet  = 'UTF-8';
					$mail->Encoding = 'base64';

					$mail->setFrom($this->from, 'SAW');
					$mail->addAddress($to, $toName);
					$mail->Subject = $subject;
					$mail->Body = $body;
					// Email simples em texto plano (sem HTML)
					$mail->isHTML(false);
					$mail->send();
					return true;
				} catch (\Throwable $e) {
					// Em caso de erro, regista mensagem e informação adicional do PHPMailer
					$err = $e->getMessage();
					if(isset($mail) && property_exists($mail,'ErrorInfo') && $mail->ErrorInfo) $err .= ' | '.$mail->ErrorInfo;
					$this->log('MAILER_PHPM_ERROR', $err . ' user=' . ($this->smtp['smtp_user'] ?? '(none)'));
					// Se estiver ativa a opção de enfileirar em caso de falha, guarda o email em fila
					if(!empty($this->smtp['smtp_queue_on_fail'])){
						$this->queue_email($to, $toName, $subject, $body, ['error'=>$err]);
						return true;
					}
					return false;
				}
			} else {
				// PHPMailer não encontrado após tentativas de autoload
				$this->log('MAILER_NO_PHPMailer','SMTP configured but PHPMailer not found. Ensure composer install or place PHPMailer in core/PHPMailer/');
				return false;
			}
		}

		// Fallback para a função nativa mail() quando o SMTP não está configurado
		// Codifica o assunto e cabeçalhos em UTF-8 para suportar acentos
		if(function_exists('mb_encode_mimeheader')){
			$encodedSubject = mb_encode_mimeheader($subject, 'UTF-8', 'B', "\r\n");
		} else {
			$encodedSubject = $subject;
		}

		$headers  = 'From: '.$this->from."\r\n";
		$headers .= 'Reply-To: '.$this->from."\r\n";
		$headers .= "MIME-Version: 1.0\r\n";
		$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
		$headers .= "Content-Transfer-Encoding: 8bit\r\n";
		$headers .= 'X-Mailer: PHP/'.phpversion();

		$res = @mail($to, $encodedSubject, $body, $headers);
		if(!$res) $this->log('MAILER_FALLBACK_FAIL',"mail() returned false for $to");
		return (bool)$res;
	}

	/**
	 * Helper específico para envio de email de recuperação de conta.
	 *
	 * Recebe o email e nome do utilizador e o link de recuperação,
	 * cria o assunto e corpo padrão e delega em sendMail().
	 */
	public function sendRecovery($toEmail, $toName, $link){
		$subject = 'Recuperação de Conta - SAW';
		$body = "Olá {$toName},\n\nClique no link para recuperar a conta (válido 15 minutos):\n{$link}\n\nSe não pediu, ignore.";
		return $this->sendMail($toEmail, $toName, $subject, $body);
	}
}
