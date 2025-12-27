<?php
/**
 * Servidor simples de imagens de salas.
 *
 * As fotos das salas são guardadas numa pasta privada
 *   private/uploads/rooms/
 * que não está diretamente acessível via URL. Este script recebe o nome do
 * ficheiro pela query string (?file=...) e, se o ficheiro existir, envia a
 * imagem com o cabeçalho Content-Type adequado.
 *
 * Medidas de segurança:
 *   - usa basename() para impedir que seja passado um caminho com subpastas
 *     (evita ataques de "path traversal");
 *   - só serve ficheiros que realmente existem nessa pasta e que sejam
 *     legíveis;
 *   - deteta o MIME type com finfo (quando disponível) para o browser saber
 *     como apresentar a imagem.
 */

// Nome do ficheiro vindo da query string; basename remove qualquer caminho
// extra para que o utilizador não consiga sair da pasta prevista
$file = $_GET['file'] ?? '';
$file = basename($file); // evita path traversal

if($file === ''){
	http_response_code(400);
	exit;
}

$path = __DIR__ . '/private/uploads/rooms/' . $file;

if(!is_file($path) || !is_readable($path)){
	http_response_code(404);
	exit;
}

// Determinar o MIME type de forma simples
$mime = 'image/jpeg';
if(function_exists('finfo_open')){
	$finfo = finfo_open(FILEINFO_MIME_TYPE);
	$detected = finfo_file($finfo, $path);
	if($detected) $mime = $detected;
	($finfo);
}

header('Content-Type: '.$mime);
header('Content-Length: '.filesize($path));
readfile($path);
exit;
