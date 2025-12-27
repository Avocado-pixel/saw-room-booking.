<?php
/**
 * Configuração privada do Mailer.
 *
 * Este ficheiro devolve um array de opções lidas pela classe Mailer em core/Mailer.php.
 * Aqui devem estar apenas credenciais e parâmetros específicos do ambiente,
 * como host SMTP, porto, utilizador, password e opções SSL.
 *
 * Boas práticas:
 * - Não deve ser comitado em repositórios públicos (contém segredos reais).
 * - Em produção, idealmente estas credenciais deveriam ser injectadas via
 *   variáveis de ambiente ou gestor de segredos, e não em texto simples.
 * - As opções smtp_options permitem ajustar verificação de certificados;
 *   em desenvolvimento pode ser necessário relaxar (allow_self_signed),
 *   mas em produção deve manter-se verificação ativa.
 */

// Configuração privada do Mailer (não comitar este ficheiro).
// Retornar um array com as chaves usadas por core/Mailer.php.
#$mail = new PHPMailer(true);
#$mail->isSMTP();
#$mail->Host = 'smtp.gmail.com';
#$mail->SMTPAuth = true;
#$mail->Username = 'tu_correo@gmail.com';
#$mail->Password = 'tu_clave_app';  // Importante
#$mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
#$mail->Port = 587;

return [
	// Servidor SMTP
	'smtp_host' => 'smtp.gmail.com',
	'smtp_port' => 587,
	'smtp_user' => 'example@gmail.com',
	'smtp_pass' => 'pass',
	'smtp_secure' => 'tls', // 'tls' ou 'ssl' conforme o provider

	// opções adicionais
	'smtp_auth_type' => 'LOGIN', // forçar método de autenticação (LOGIN/PLAIN/LOGIN-AUTH)
	'smtp_timeout' => 30,        // timeout em segundos
	'smtp_debug' => false,      // debug desactivado por omissão
	'smtp_queue_on_fail' => true, // Se true, grava mensagens na pasta private/mail_queue/ quando o envio SMTP falhar

	// Opcional: ajustar opções SSL se necessário (ex.: allow_self_signed apenas em dev)
	'smtp_options' => [
		'ssl' => [
			'verify_peer' => true,
			'verify_peer_name' => true,
			'allow_self_signed' => false,
		],
	],
	// Endereço do remetente
	'from' => 'example@gmail.com',
];
