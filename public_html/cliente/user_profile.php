<?php
/**
 * Página de perfil do utilizador.
 *
 * Esta página mostra os dados pessoais (nome, email, NIF, telemóvel, morada
 * e foto) e permite:
 *   - iniciar o fluxo de atualização de perfil (dados + foto), que é depois
 *     tratado pela ação profile_update;
 *   - alterar a password;
 *   - configurar autenticação de dois fatores (2FA) através de uma app
 *     (Google Authenticator, Authy, etc.).
 *
 * A página adapta-se ao tipo de utilizador:
 *   - se o perfil em sessão for 'admin', usa o layout de administração;
 *   - caso contrário, usa o layout de cliente.
 *
 * Também trata localmente o POST relacionado com 2FA (iniciar configuração
 * e confirmar código), usando o helper TwoFAHelper e registando a ativação
 * em Logger::audit_user.
 */

// Garante sessão ativa e que o utilizador esteja autenticado
if(!isset($_SESSION)) session_start();
if(empty($_SESSION['user_id'])) { header('Location: /index.php?page=login'); exit; }

if(!isset($pdo)) require_once __DIR__ . '/../bootstrap.php';

// escolher layout conforme o perfil
$isAdmin = (($_SESSION['perfil'] ?? '') === 'admin');
if($isAdmin){
	require_once __DIR__ . '/../core/AdminLayout.php';
} else {
	require_once __DIR__ . '/../core/ClientLayout.php';
}

// garantir Security disponível
if(!class_exists('Security')) require_once __DIR__ . '/../core/security.php';

$uid = (int)$_SESSION['user_id'];

// --- 2FA: tratar POST local (twofa_stage) antes de carregar o utilizador ---
if($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['twofa_stage'])){
	$post = \Security::clean_array($_POST);

	if(!\Security::verify_csrf($post['csrf'] ?? '')){
		$_SESSION['flash_error'] = 'Sessão inválida. Tente novamente.';
		header('Location: /index.php?page=user_profile'); exit;
	}

	// carregar email e segredo 2FA do utilizador
	$stTmp = $pdo->prepare("SELECT email,twofa_secret FROM utilizadores WHERE id = :id LIMIT 1");
	$stTmp->execute([':id'=>$uid]);
	$uTmp = $stTmp->fetch(PDO::FETCH_ASSOC);
	if(!$uTmp){
		$_SESSION['flash_error'] = 'Utilizador não encontrado.';
		header('Location: /index.php?page=user_profile'); exit;
	}

	require_once __DIR__ . '/../core/twofactorauth';

	$stage2fa = $post['twofa_stage'];
	switch($stage2fa){
		case 'start':
			// gerar segredo + QR e guardar em sessão
			$gen = TwoFAHelper::generateForUser('SAW', $uTmp['email']);
			$_SESSION['twofa_pending'] = [
				'secret'  => $gen['secret'],
				'qr'      => $gen['qr'],
				'created' => time(),
			];
			$_SESSION['flash_success'] = 'Digitalize o QR na app de autenticação e introduza o código de 6 dígitos.';
			break;

		case 'confirm':
			$code    = trim($post['twofa_code'] ?? '');
			$pending = $_SESSION['twofa_pending'] ?? null;

			if(!$pending || empty($pending['secret'])){
				$_SESSION['flash_error'] = 'Não existe configuração de 2FA pendente.';
				break;
			}

			if(!TwoFAHelper::verifyCode($pending['secret'], $code, 'SAW', 1)){
				$_SESSION['flash_error'] = 'Código 2FA inválido. Verifique na sua app de autenticação.';
				break;
			}

			// guardar segredo na BD
			$up2 = $pdo->prepare("UPDATE utilizadores SET twofa_secret = :s WHERE id = :id");
			$up2->execute([':s'=>$pending['secret'], ':id'=>$uid]);

			// logar ativação de 2FA
			if(isset($logger) && method_exists($logger,'audit_user')){
				$logger->audit_user($uid,'2FA_ENABLED','Autenticação de dois fatores ativada pelo utilizador');
			}

			unset($_SESSION['twofa_pending']);
			$_SESSION['flash_success'] = 'Autenticação de dois fatores ativada com sucesso.';
			break;

		case 'disable':
			$code = trim($post['twofa_code'] ?? '');

			// garantir que existe 2FA ativo
			if(empty($uTmp['twofa_secret'])){
				$_SESSION['flash_error'] = 'A autenticação de dois fatores não está ativa nesta conta.';
				break;
			}

			if($code === ''){
				$_SESSION['flash_error'] = 'Indique o código de 6 dígitos da sua app de autenticação.';
				break;
			}

			// validar código atual contra o segredo guardado
			if(!TwoFAHelper::verifyCode($uTmp['twofa_secret'], $code, 'SAW', 1)){
				$_SESSION['flash_error'] = 'Código 2FA inválido. Verifique na sua app de autenticação.';
				break;
			}

			// remover segredo 2FA da conta
			$up3 = $pdo->prepare("UPDATE utilizadores SET twofa_secret = NULL WHERE id = :id");
			$up3->execute([':id'=>$uid]);

			// logar desativação de 2FA
			if(isset($logger) && method_exists($logger,'audit_user')){
				$logger->audit_user($uid,'2FA_DISABLED','Autenticação de dois fatores desativada pelo utilizador');
			}

			$_SESSION['flash_success'] = 'Autenticação de dois fatores desativada com sucesso.';
			break;

		default:
			$_SESSION['flash_error'] = 'Ação de 2FA inválida.';
	}

	header('Location: /index.php?page=user_profile'); exit;
}

// carregar dados do utilizador (inclui twofa_secret)
$st = $pdo->prepare("SELECT id,nome,email,nif,telemovel,morada,foto,twofa_secret FROM utilizadores WHERE id = :id LIMIT 1");
$st->execute([':id'=>$uid]);
$user = $st->fetch();
if(!$user){ echo "Utilizador não encontrado."; exit; }

$hasTwoFA     = !empty($user['twofa_secret'] ?? null);
$pendingTwoFA = $_SESSION['twofa_pending'] ?? null;

// flash messages
$flashErr = $_SESSION['flash_error'] ?? null; if($flashErr) unset($_SESSION['flash_error']);
$flashOk  = $_SESSION['flash_success'] ?? null; if($flashOk) unset($_SESSION['flash_success']);

// foto (servida via endpoint protegido user_photo)
$fotoSrc = '';
if(!empty($user['foto'])){
	$fotoSrc = '/index.php?action=user_photo&uid='.(int)$user['id'];
}

// função de render comum ao admin e cliente
$renderFn = function() use ($user, $flashErr, $flashOk, $fotoSrc, $hasTwoFA, $pendingTwoFA){
	?>
	<div style="max-width:1000px;margin:0 auto;">
	  <h1 style="margin:0 0 12px 0;font-size:1.7rem;">Perfil</h1>
	  <p style="margin:0 0 20px 0;font-size:0.95rem;color:#6b7280;">
	    Veja e atualize os seus dados pessoais e credenciais de acesso.
	  </p>

	  <?php if($flashErr): ?>
	    <div style="margin-bottom:14px;padding:10px 12px;border-radius:8px;background:#fef2f2;color:#b91c1c;font-size:0.9rem;">
	      <?php echo htmlspecialchars($flashErr); ?>
	    </div>
	  <?php endif; ?>
	  <?php if($flashOk): ?>
	    <div style="margin-bottom:14px;padding:10px 12px;border-radius:8px;background:#ecfdf3;color:#166534;font-size:0.9rem;">
	      <?php echo htmlspecialchars($flashOk); ?>
	    </div>
	  <?php endif; ?>

	  <!-- SECÇÃO 1: Cartão de perfil (foto + dados principais) -->
	  <section class="client-card" style="display:flex;flex-wrap:wrap;gap:20px;align-items:center;margin-bottom:20px;">
	    <div style="flex:0 0 140px;display:flex;flex-direction:column;align-items:center;gap:8px;">
	      <?php if($fotoSrc): ?>
	        <img src="<?php echo htmlspecialchars($fotoSrc); ?>"
	             alt="Foto de perfil"
	             style="width:120px;height:120px;border-radius:999px;object-fit:cover;
	                    border:3px solid rgba(255,255,255,0.9);box-shadow:0 4px 12px rgba(15,23,42,0.25);">
	      <?php else: ?>
	        <div style="width:120px;height:120px;border-radius:999px;background:#e5e7eb;
	                    display:flex;align-items:center;justify-content:center;
	                    color:#9ca3af;font-weight:700;font-size:2rem;">
	          <?php echo strtoupper(substr($user['nome'],0,1)); ?>
	        </div>
	      <?php endif; ?>
	      <span style="font-size:0.8rem;color:#6b7280;">Foto de perfil</span>
	    </div>

	    <div style="flex:1;min-width:220px;display:flex;flex-direction:column;gap:10px;">
	      <div>
	        <div style="font-size:1.2rem;font-weight:700;color:#0f172a;"><?php echo htmlspecialchars($user['nome']); ?></div>
	        <div style="font-size:0.9rem;color:#6b7280;"><?php echo htmlspecialchars($user['email']); ?></div>
	      </div>
	      <dl style="margin:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;font-size:0.9rem;color:#4b5563;">
	        <div>
	          <dt style="font-weight:600;color:#6b7280;">NIF</dt>
	          <dd style="margin:2px 0 0 0;"><?php echo htmlspecialchars($user['nif'] ?? ''); ?></dd>
	        </div>
	        <div>
	          <dt style="font-weight:600;color:#6b7280;">Telemóvel</dt>
	          <dd style="margin:2px 0 0 0;"><?php echo htmlspecialchars($user['telemovel'] ?? ''); ?></dd>
	        </div>
	        <div style="grid-column:1/-1;">
	          <dt style="font-weight:600;color:#6b7280;">Morada</dt>
	          <dd style="margin:2px 0 0 0;"><?php echo htmlspecialchars($user['morada'] ?? ''); ?></dd>
	        </div>
	      </dl>
	    </div>
	  </section>

	  <!-- LAYOUT 2 colunas: esquerda = dados pessoais, direita = password + 2FA -->
	  <div style="display:grid;grid-template-columns:minmax(0,2.1fr) minmax(0,1.7fr);gap:18px;align-items:flex-start;">

	    <!-- COLUNA ESQUERDA: edição de dados pessoais -->
	    <section class="client-card">
	      <h2 style="margin:0 0 8px 0;font-size:1.1rem;">Editar dados pessoais</h2>
	      <p style="margin:0 0 14px 0;font-size:0.88rem;color:#6b7280;line-height:1.4;">
	        Passo 1: peça um código. Passo 2: insira o código recebido para aplicar as alterações.
	      </p>

	      <!-- Passo 1: pedir código com os novos dados -->
	      <form method="post" action="/index.php?action=profile_update" enctype="multipart/form-data" style="margin-bottom:14px;">
	        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
	        <input type="hidden" name="stage" value="send_code">
	        <div class="client-form-row">
	          <label>Nome</label>
	          <input name="nome" value="<?php echo htmlspecialchars($user['nome']); ?>" required>
	        </div>
	        <div class="client-form-row">
	          <label>Email</label>
	          <input type="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" required>
	        </div>
	        <div class="client-form-row">
	          <label>Telemóvel</label>
	          <input name="telemovel" value="<?php echo htmlspecialchars($user['telemovel']); ?>">
	        </div>
	        <div class="client-form-row">
	          <label>Morada</label>
	          <input name="morada" value="<?php echo htmlspecialchars($user['morada']); ?>">
	        </div>
	        <div class="client-form-row">
	          <label>Nova foto (JPEG/PNG, opcional)</label>
	          <input type="file" name="foto" accept="image/jpeg,image/png">
	        </div>
	        <button class="client-btn" type="submit">Pedir código por email</button>
	      </form>

	      <!-- Passo 2: confirmar com código -->
	      <form method="post" action="/index.php?action=profile_update">
	        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
	        <input type="hidden" name="stage" value="confirm_update">
	        <div class="client-form-row">
	          <label>Código recebido por email</label>
	          <input name="code" maxlength="6" pattern="\d{6}" placeholder="Ex.: 123456">
	        </div>
	        <button class="client-btn primary" type="submit">Confirmar alterações</button>
	      </form>
	    </section>

	    <!-- COLUNA DIREITA: password + 2FA -->
	    <div style="display:flex;flex-direction:column;gap:16px;">

	      <!-- Alterar password -->
	      <section class="client-card">
	        <h2 style="margin:0 0 8px 0;font-size:1.05rem;">Alterar password</h2>
	        <p style="margin:0 0 12px 0;font-size:0.86rem;color:#6b7280;">
	          Indique a sua senha atual e a nova senha que pretende utilizar.
	        </p>
	        <form id="pwdForm" method="post" action="/index.php?action=profile_update">
	          <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
	          <input type="hidden" name="stage" value="set_password">
	          <div class="client-form-row">
	            <label>Senha atual</label>
	            <input type="password" name="current_password" required>
	          </div>
	          <div class="client-form-row">
	            <label>Nova senha</label>
	            <input type="password" name="password" required>
	          </div>
	          <div class="client-form-row">
	            <label>Confirmar nova senha</label>
	            <input type="password" name="password_confirm" required>
	          </div>
	          <button class="client-btn primary" type="submit">Alterar senha</button>
	        </form>
	      </section>

	      <!-- 2FA -->
	      <section class="client-card">
	        <h2 style="margin:0 0 8px 0;font-size:1.05rem;">Autenticação de dois fatores (2FA)</h2>
	        <p style="margin:0 0 10px 0;font-size:0.86rem;color:#6b7280;">
	          Proteja a sua conta com um código de 6 dígitos gerado por uma app (Google Authenticator, Authy, etc.).
	        </p>

	        <?php if($hasTwoFA): ?>
	          <p style="font-size:0.88rem;color:#166534;margin:0 0 10px 0;">
	            A autenticação de dois fatores está <strong>ativa</strong> para esta conta.
	          </p>
	          <p style="font-size:0.82rem;color:#6b7280;margin:0 0 10px 0;">
	            Para desativar, introduza um código válido da sua app de autenticação.
	          </p>
	          <form method="post" action="/index.php?page=user_profile">
	            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
	            <input type="hidden" name="twofa_stage" value="disable">
	            <div class="client-form-row">
	              <label>Código 2FA (6 dígitos)</label>
	              <input type="text" name="twofa_code" maxlength="6" pattern="\d{6}" required placeholder="Ex.: 123456">
	            </div>
	            <button class="client-btn" type="submit" style="background:#fee2e2;color:#b91c1c;border-color:#fecaca;">
	              Desativar autenticação de dois fatores
	            </button>
	          </form>
	        <?php elseif(!empty($pendingTwoFA['qr'] ?? null)): ?>
	          <div style="margin-bottom:10px;text-align:center;">
	            <p style="font-size:0.86rem;color:#6b7280;margin-bottom:8px;">
	              1. Digitalize este QR na sua app de autenticação.
	            </p>
	            <img src="<?php echo htmlspecialchars($pendingTwoFA['qr']); ?>" alt="QR Code 2FA">
	          </div>
	          <form method="post" action="/index.php?page=user_profile">
	            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
	            <input type="hidden" name="twofa_stage" value="confirm">
	            <div class="client-form-row">
	              <label>2. Código de 6 dígitos</label>
	              <input type="text" name="twofa_code" maxlength="6" pattern="\d{6}" required placeholder="Ex.: 123456">
	            </div>
	            <button class="client-btn primary" type="submit">Ativar 2FA</button>
	          </form>
	        <?php else: ?>
	          <form method="post" action="/index.php?page=user_profile">
	            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
	            <input type="hidden" name="twofa_stage" value="start">
	            <button class="client-btn" type="submit">Ativar autenticação de dois fatores</button>
	          </form>
	        <?php endif; ?>
	      </section>

	    </div>
	  </div>

	  <script>
	  // Validação simples no cliente para o formulário de password
	  document.getElementById('pwdForm').addEventListener('submit', function(e){
	    var f = e.target;
	    var p = f.password.value || '';
	    var p2 = f.password_confirm.value || '';
	    if(p.length < 6){
	      e.preventDefault();
	      alert('Senha muito curta (mínimo 6 caracteres).');
	    } else if(p !== p2){
	      e.preventDefault();
	      alert('As senhas não coincidem.');
	    }
	  });
	  </script>
	</div>
	<?php
};

// chamar layout adequado
if($isAdmin){
	render_admin_page('Perfil do administrador', $renderFn);
} else {
	render_client_page('Perfil do Cliente', $renderFn);
}
?>
