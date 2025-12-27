<?php
/**
 * Página de reserva de uma sala por parte de um utilizador autenticado.
 *
 * Aqui o utilizador escolhe a data, a hora de início e a duração da reserva
 * para uma sala específica. O código valida cuidadosamente:
 *   - se o utilizador está autenticado;
 *   - se a sala existe e não foi eliminada;
 *   - se o pedido tem um token CSRF válido (proteção contra ataques de "request" forjados);
 *   - se a data/hora têm formato correto e não ficam no passado;
 *   - se a hora está alinhada em blocos de 30 minutos;
 *   - se a duração é múltiplo de 30 minutos;
 *   - se não há conflito com outras reservas dessa sala no mesmo período.
 *
 * Em caso de sucesso, grava a reserva na base de dados e regista um evento
 * de auditoria em Logger (ficheiro reserva_salas.txt). Em caso de erro,
 * devolve uma mensagem amigável ao utilizador.
 */

// Garante que a sessão está iniciada para poder usar $_SESSION
if(!isset($_SESSION)) session_start();
// Se o utilizador não estiver autenticado, é redirecionado para o login
if(empty($_SESSION['user_id'])){
	$next = urlencode($_SERVER['REQUEST_URI'] ?? '/index.php?page=user_reservar');
	header('Location: /index.php?page=login&next='.$next);
	exit;
}
// Carrega o bootstrap (liga à base de dados, logger, etc.) e helper de segurança
if(!isset($pdo)) require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../core/security.php';

// ID do utilizador autenticado (vem da sessão) e ID da sala escolhida
$userId = (int)$_SESSION['user_id'];
$salaId = (int)($_GET['sala_id'] ?? $_POST['sala_id'] ?? 0);

// Carregar dados básicos da sala escolhida, garantindo que existe e não está eliminada
if($salaId <= 0){
	echo "Sala inválida."; exit;
}
$st = $pdo->prepare("SELECT id,nome FROM salas WHERE id = :id AND estado_registo != 'eliminado' LIMIT 1");
$st->execute([':id'=>$salaId]);
$sala = $st->fetch(PDO::FETCH_ASSOC);
if(!$sala){
	echo "Sala não encontrada."; exit;
}

// Mensagens temporárias (flash) para feedback ao utilizador
$flashErr = $_SESSION['flash_error'] ?? null; if($flashErr) unset($_SESSION['flash_error']);
$flashOk  = $_SESSION['flash_success'] ?? null; if($flashOk) unset($_SESSION['flash_success']);

// --- POST: criar reserva ---
if($_SERVER['REQUEST_METHOD'] === 'POST'){
	// Limpa os dados do formulário para reduzir o risco de injeções XSS/SQL
	$post = \Security::clean_array($_POST);

	// Verifica o token CSRF para garantir que o pedido veio realmente deste site
	if(!\Security::verify_csrf($post['csrf'] ?? '')){
		$_SESSION['flash_error'] = 'Sessão inválida. Tente novamente.';
		header('Location: /index.php?page=user_reservar&sala_id='.$salaId);
		exit;
	}

	// Campos principais vindos do formulário
	$data = trim($post['data'] ?? '');      // data da reserva (AAAA-MM-DD)
	$hora = trim($post['hora'] ?? '');      // hora de início (HH:MM)
	$dur  = (int)($post['duracao'] ?? 30);  // duração em minutos

	// Usar a mesma lógica centralizada de validação/verificação de conflitos
	$val = ReservationHelper::validateInterval($pdo, $data, $hora, $dur, $salaId, null);
	if(!$val['ok']){
		$_SESSION['flash_error'] = $val['error'] ?? 'Dados de reserva inválidos.';
		header('Location: /index.php?page=user_reservar&sala_id='.$salaId); exit;
	}

	$inicioSql = $val['inicioSql'];
	$fimSql    = $val['fimSql'];

	try {
		$token = bin2hex(random_bytes(8));

		$ins = $pdo->prepare("
			INSERT INTO reservas (user_id,sala_id,data_inicio,data_fim,token_partilha)
			VALUES (:u,:s,:di,:df,:t)
		");
		$ins->execute([
			':u'  => $userId,
			':s'  => $salaId,
			':di' => $inicioSql,
			':df' => $fimSql,
			':t'  => $token
		]);

		// Regista no ficheiro de auditoria de reservas que o utilizador criou uma nova reserva
		if(isset($logger) && method_exists($logger,'audit_reserva')){
			$detalhes = "Reserva sala {$salaId} de {$inicioSql} a {$fimSql} (token={$token})";
			$logger->audit_reserva($userId,'RESERVA_CRIADA',$detalhes);
		}

		$_SESSION['flash_success'] = 'Reserva criada com sucesso.';
		header('Location: /index.php?page=user_rooms');
		exit;
	} catch(Exception $e){
		$_SESSION['flash_error'] = 'Erro ao criar reserva. Tente novamente.';
		header('Location: /index.php?page=user_reservar&sala_id='.$salaId); exit;
	}
}

// --- GET: mostrar formulário de reserva ---
?>
<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8">
  <title>Reservar sala - SAW</title>
  <link rel="stylesheet" href="/assets/css/style_client.css">
</head>
<body>
  <header class="client-topbar">
    <div class="client-topbar-left">
      <div class="client-logo-mark"></div>
      <div class="client-logo-text">SAW — Reservar sala</div>
    </div>
    <div class="client-topbar-actions">
      <a href="/index.php?page=user_rooms" class="client-nav-link">Salas</a>
      <a href="/index.php?page=user_profile" class="client-nav-link">Perfil</a>
      <a href="/index.php?action=logout" class="client-logout">Sair</a>
    </div>
  </header>

  <main class="client-wrap" role="main">
    <div style="max-width:520px;margin:0 auto;"><!-- novo wrapper para reduzir o “quadro” -->
      <div class="client-card">
        <h2 style="margin-top:0;">Reservar: <?php echo htmlspecialchars($sala['nome']); ?></h2>

        <?php if($flashErr): ?>
          <div style="margin-bottom:10px;color:#b91c1c;font-size:0.9rem;"><?php echo htmlspecialchars($flashErr); ?></div>
        <?php endif; ?>
        <?php if($flashOk): ?>
          <div style="margin-bottom:10px;color:#166534;font-size:0.9rem;"><?php echo htmlspecialchars($flashOk); ?></div>
        <?php endif; ?>

        <p style="font-size:0.9rem;color:#6b7280;">
          Escolha a data e a hora de início. As reservas são feitas em blocos de 30 minutos.
        </p>

        <form method="post" action="/index.php?page=user_reservar">
          <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
          <input type="hidden" name="sala_id" value="<?php echo (int)$sala['id']; ?>">

          <div class="client-form-row">
            <label>Data</label>
            <input type="date" name="data" required>
          </div>

          <div class="client-form-row">
            <label>Hora de início</label>
            <select name="hora" required>
              <?php
              for($h=8; $h<=20; $h++){
                foreach([0,30] as $m){
                  $label = sprintf('%02d:%02d', $h, $m);
                  echo '<option value="'.$label.'">'.$label.'</option>';
                }
              }
              ?>
            </select>
          </div>

          <div class="client-form-row">
            <label>Duração</label>
            <select name="duracao" required>
              <option value="30">30 minutos</option>
              <option value="60">1 hora</option>
              <option value="90">1h30</option>
              <option value="120">2 horas</option>
            </select>
          </div>

          <button class="client-btn primary" type="submit">Confirmar reserva</button>
        </form>
      </div>
    </div>
  </main>
</body>
</html>
