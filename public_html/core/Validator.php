<?php
/**
 * Classe de validação simples para campos específicos (NIF, nome, password,
 * sanitização de campos de formulário e validação de imagem de perfil).
 *
 * Toda a lógica existente foi pensada para este projeto em concreto,
 * pelo que estes métodos são helpers reutilizáveis em vários ficheiros.
 */
class Validator {
	/**
	 * Valida NIF português usando o algoritmo módulo 11.
	 *
	 * Passos:
	 * - Remove todos os caracteres não numéricos.
	 * - Exige exatamente 9 dígitos.
	 * - Calcula o dígito de controlo e compara com o último dígito.
	 */
	public static function validateNIF_PT(string $nif): bool {
		$nif = preg_replace('/\D/', '', $nif);
		if(strlen($nif) !== 9) return false;
		$digits = str_split($nif);
		$sum = 0;
		// multiplica cada um dos 8 primeiros dígitos por um peso decrescente de 9 a 2
		for($i=0;$i<8;$i++){
			$sum += (int)$digits[$i] * (9 - $i);
		}
		$remainder = $sum % 11;
		$check = 11 - $remainder;
		if($check >= 10) $check = 0;
		// compara o dígito de controlo calculado com o 9.º dígito do NIF
		return ((int)$digits[8] === $check);
	}

	/**
	 * Valida o nome completo do utilizador.
	 *
	 * Regras principais:
	 * - Faz trim ao início e fim.
	 * - Comprimento mínimo de 4 caracteres.
	 * - Só permite letras (incluindo acentos), espaços, apóstrofo e hífen.
	 * - Exige pelo menos 2 "palavras" com 2 ou mais letras cada (ex.: "Ana Silva").
	 */
	public static function validateName(string $name): bool {
		$name = trim($name);
		if(mb_strlen($name) < 4) return false;
		// Verifica se só contém caracteres permitidos
		if(!preg_match('/^[\p{L} \'-]+$/u', $name)) return false;
		// Divide por espaços e conta quantas partes têm pelo menos 2 letras
		$parts = preg_split('/\s+/', $name);
		$validParts = 0;
		foreach($parts as $p) if(mb_strlen($p) >= 2) $validParts++;
		return $validParts >= 2;
	}

	/**
	 * Valida uma password "forte":
	 * - mínimo 10 caracteres
	 * - pelo menos 1 letra maiúscula
	 * - pelo menos 1 letra minúscula
	 * - pelo menos 1 dígito
	 * - pelo menos 1 símbolo (qualquer caractere não alfanumérico)
	 */
	public static function validatePasswordStrong(string $pass): bool {
		if(strlen($pass) < 10) return false;
		if(!preg_match('/[A-Z]/', $pass)) return false;
		if(!preg_match('/[a-z]/', $pass)) return false;
		if(!preg_match('/\d/',    $pass)) return false;
		if(!preg_match('/[^A-Za-z0-9]/', $pass)) return false;
		return true;
	}

	// Sanitizações reutilizáveis (iguais às usadas no register.php)
	public static function sanitizeNome(string $nome): string {
		$nome = trim($nome);
		return filter_var($nome, FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH);
	}

	/**
	 * Sanitiza um email, removendo espaços e aplicando FILTER_SANITIZE_EMAIL.
	 */
	public static function sanitizeEmail(string $email): string {
		$email = trim($email);
		return filter_var($email, FILTER_SANITIZE_EMAIL);
	}

	/**
	 * Sanitiza uma morada, removendo caracteres de controlo.
	 */
	public static function sanitizeMorada(string $morada): string {
		$morada = trim($morada);
		return filter_var($morada, FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH);
	}

	/**
	 * Sanitiza o número de telemóvel, removendo tudo o que não for dígito.
	 */
	public static function sanitizeTelemovel(string $tel): string {
		$tel = trim($tel);
		return preg_replace('/\D/', '', $tel);
	}

	/**
	 * Valida upload de foto de perfil.
	 * - $required = true obriga a ter ficheiro, false torna-o opcional.
	 * - Garante máx. 2MB, JPEG/PNG e que é realmente imagem.
	 * Retorna: ['ok'=>bool,'ext'=>?string,'error'=>?string]
	 */
	public static function validateProfileImage(?array $file, bool $required = false, int $maxBytes = 2097152): array {
		if(empty($file) || $file['error'] === UPLOAD_ERR_NO_FILE){
			if($required){
				return ['ok'=>false,'ext'=>null,'error'=>'Envie uma foto de perfil válida.'];
			}
			return ['ok'=>true,'ext'=>null,'error'=>null];
		}
		if($file['error'] !== UPLOAD_ERR_OK){
			return ['ok'=>false,'ext'=>null,'error'=>'Erro no upload da imagem.'];
		}
		if(($file['size'] ?? 0) > $maxBytes){
			return ['ok'=>false,'ext'=>null,'error'=>'Foto demasiado grande (máx 2MB).'];
		}
		$finfo = new finfo(FILEINFO_MIME_TYPE);
		$mime = $finfo->file($file['tmp_name']);
		$allowed = ['image/jpeg'=>'jpg','image/png'=>'png'];
		if(!isset($allowed[$mime])){
			return ['ok'=>false,'ext'=>null,'error'=>'Formato da imagem inválido. Apenas JPEG/PNG.'];
		}
		if(@getimagesize($file['tmp_name']) === false){
			return ['ok'=>false,'ext'=>null,'error'=>'Imagem inválida.'];
		}
		return ['ok'=>true,'ext'=>$allowed[$mime],'error'=>null];
	}
}

/**
 * Paginator: helper genérico para paginação + pesquisa simples.
 *
 * Uso típico (em qualquer ficheiro):
 *
 *   $p = new Paginator($_GET, 5); // 5 por página
 *   $sqlBase = "FROM salas WHERE estado_registo != 'eliminado'";
 *   if($p->hasSearch()){
 *       $sqlBase .= " AND nome LIKE :q";
 *       $params[':q'] = '%'.$p->getSearch().'%';
 *   }
 *   // contar total
 *   $stmt = $pdo->prepare("SELECT COUNT(*) ".$sqlBase);
 *   $stmt->execute($params);
 *   $p->setTotal((int)$stmt->fetchColumn());
 *
 *   // buscar registos
 *   $stmt = $pdo->prepare("SELECT id,nome,capacidade,estado,foto ".$sqlBase." ".$p->limitSql());
 *   $stmt->execute($params);
 *   $rows = $stmt->fetchAll();
 *
 *   // no HTML:
 *   echo $p->renderSearchForm();
 *   // ...tabela com $rows...
 *   echo $p->renderLinks();
 */
class Paginator {
	private int $page;
	private int $limit;
	private int $total = 0;
	private string $search;
	private array $queryBase;

	public function __construct(array $query, int $defaultLimit = 5, string $pageParam = 'p', string $searchParam = 'q'){
		$this->page  = max(1, (int)($query[$pageParam]  ?? 1));
		$this->limit = max(1, (int)($query['limit'] ?? $defaultLimit));
		$this->search = trim((string)($query[$searchParam] ?? ''));
		// guardar query base para gerar links mantendo outros parâmetros
		$this->queryBase = $query;
		unset($this->queryBase[$pageParam], $this->queryBase['limit']);
	}

	public function getPage(): int { return $this->page; }
	public function getLimit(): int { return $this->limit; }
	public function getOffset(): int { return ($this->page - 1) * $this->limit; }

	public function hasSearch(): bool { return $this->search !== ''; }
	public function getSearch(): string { return $this->search; }

	public function setTotal(int $total): void { $this->total = max(0, $total); }
	public function getTotal(): int { return $this->total; }

	public function getTotalPages(): int {
		if($this->limit <= 0) return 1;
		return max(1, (int)ceil($this->total / $this->limit));
	}

	// devolve um fragmento "LIMIT :limit OFFSET :offset" para usar na query
	public function limitSql(): string {
		return " LIMIT ".$this->limit." OFFSET ".$this->getOffset()." ";
	}

	// renderiza um pequeno formulário de pesquisa (GET) baseado no query atual
	public function renderSearchForm(string $placeholder = 'Pesquisar...', string $param = 'q'): string {
		$q = htmlspecialchars($this->search, ENT_QUOTES, 'UTF-8');
		// manter outros parâmetros no form (hidden inputs)
		$html = '<form method="get" style="margin-bottom:10px;display:flex;gap:6px;align-items:center;">';
		foreach($this->queryBase as $k=>$v){
			$k = htmlspecialchars($k, ENT_QUOTES, 'UTF-8');
			$v = htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
			$html .= '<input type="hidden" name="'.$k.'" value="'.$v.'">';
		}
		$html .= '<input type="text" name="'.htmlspecialchars($param,ENT_QUOTES,'UTF-8').'" value="'.$q.'" placeholder="'.$placeholder.'" style="padding:6px 8px;border-radius:6px;border:1px solid #d1d5db;min-width:180px;">';
		$html .= '<button type="submit" style="padding:6px 10px;border-radius:6px;border:0;background:#004ba0;color:#fff;font-weight:600;font-size:0.9rem;cursor:pointer;">Procurar</button>';
		$html .= '</form>';
		return $html;
	}

	// renderiza links de paginação simples (Anterior / números / Seguinte)
	public function renderLinks(string $pageParam = 'p'): string {
		$totalPages = $this->getTotalPages();
		if($totalPages <= 1) return '';

		// base da querystring
		$base = $this->queryBase;
		$baseStr = function(array $extra) use ($base){
			$q = array_merge($base, $extra);
			$parts = [];
			foreach($q as $k=>$v){
				$parts[] = urlencode((string)$k).'='.urlencode((string)$v);
			}
			return '?'.implode('&', $parts);
		};

		$html = '<nav aria-label="Paginação" style="margin-top:10px;font-size:0.9rem;"><ul style="display:flex;list-style:none;padding:0;margin:0;gap:4px;flex-wrap:wrap;">';

		// anterior
		if($this->page > 1){
			$html .= '<li><a href="'.$baseStr([$pageParam => $this->page - 1]).'" style="padding:4px 8px;border-radius:6px;border:1px solid #d1d5db;text-decoration:none;color:#111827;">«</a></li>';
		}

		// alguns links à volta da página atual
		$start = max(1, $this->page - 2);
		$end   = min($totalPages, $this->page + 2);
		for($i=$start; $i<=$end; $i++){
			if($i === $this->page){
				$html .= '<li><span style="padding:4px 8px;border-radius:6px;background:#004ba0;color:#fff;font-weight:600;">'.$i.'</span></li>';
			} else {
				$html .= '<li><a href="'.$baseStr([$pageParam => $i]).'" style="padding:4px 8px;border-radius:6px;border:1px solid #d1d5db;text-decoration:none;color:#111827;">'.$i.'</a></li>';
			}
		}

		// seguinte
		if($this->page < $totalPages){
			$html .= '<li><a href="'.$baseStr([$pageParam => $this->page + 1]).'" style="padding:4px 8px;border-radius:6px;border:1px solid #d1d5db;text-decoration:none;color:#111827;">»</a></li>';
		}

		$html .= '</ul></nav>';
		return $html;
	}
}