<?php

/**
 * Classe responsável por funções de segurança da aplicação,
 * nomeadamente limpeza de dados e protecção contra CSRF.
 */
class Security {
	/**
	 * Limpa um valor individual (string ou array) para evitar
	 * injecções de código HTML/JS e caracteres inválidos.
	 *
	 * - Se for um array, limpa recursivamente todos os valores.
	 * - Remove espaços no início e fim.
	 * - Remove caracteres de controlo.
	 * - Remove quaisquer tags HTML.
	 * - Converte caracteres especiais para entidades HTML (para saída segura).
	 */
	public static function clean($value){
		// Se for array, aplica a mesma limpeza a cada elemento
		if(is_array($value)){
			return array_map([self::class,'clean'], $value);
		}
		// Garante que é string e remove espaços em branco nas extremidades
		$value = trim((string)$value);
		// Remove caracteres de controlo (invisíveis) que podem ser maliciosos
		$value = preg_replace('/[\x00-\x1F\x7F]/u','',$value);
		// Remove quaisquer tags HTML para evitar injecção de código
		$value = strip_tags($value);
		// Converte caracteres especiais em entidades HTML para saída segura
		return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
	}

	/**
	 * Limpa todos os valores de um array associativo usando o método clean().
	 * Útil, por exemplo, para limpar os dados de $_POST ou $_GET.
	 */
	public static function clean_array(array $arr){
		$res = [];
		foreach($arr as $k=>$v) $res[$k] = self::clean($v);
		return $res;
	}

	/**
	 * Gera (se ainda não existir) e devolve o token CSRF armazenado em sessão.
	 *
	 * Este token deve ser incluído nos formulários para proteger
	 * contra ataques de Cross-Site Request Forgery (CSRF).
	 */
	public static function csrf_token(){
		// Se não existir token CSRF em sessão, cria um novo token aleatório
		if(empty($_SESSION['csrf_token'])){
			$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
			// Guarda também o momento em que o token foi criado
			$_SESSION['csrf_time'] = time();
		}
		return $_SESSION['csrf_token'];
	}

	/**
	 * Verifica se o token CSRF recebido é válido:
	 *
	 * - Confere se existe token em sessão e se foi enviado um token.
	 * - Verifica se o token não expirou (aqui 1 hora).
	 * - Compara de forma segura o token da sessão com o token recebido.
	 */
	public static function verify_csrf($token){
		// Se não houver token em sessão ou não foi enviado token, é inválido
		if(empty($_SESSION['csrf_token']) || !$token) return false;
		// Expiração opcional do token: 1 hora após a criação
		if(($_SESSION['csrf_time'] ?? 0) + 3600 < time()) {
			// Se expirou, remove o token da sessão e considera inválido
			unset($_SESSION['csrf_token']);
			return false;
		}
		// Compara os tokens de forma segura, protegendo contra ataques de timing
		return hash_equals($_SESSION['csrf_token'], $token);
	}
}
