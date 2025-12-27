<?php
/**
 * Página pública de login.
 *
 * Esta view apresenta o formulário de autenticação com:
 *   - campos de email e password;
 *   - opção "remember me" (para cookie de sessão prolongada);
 *   - links para pedido de recuperação de senha e validação de conta;
 *   - integração com autenticação de dois fatores (2FA) através de um
 *     modal que é mostrado quando o servidor indica que falta o código.
 *
 * O formulário não envia diretamente para uma página PHP específica; em vez
 * disso, um script JavaScript faz um pedido AJAX para /index.php com
 * action=login. O router em index.php encaminha então esse pedido para a
 * lógica de autenticação em routes/auth.php, que devolve JSON indicando
 * sucesso, erro ou necessidade de 2FA.
 */
// View de login: usa style_public.css e topbar; envia via AJAX para index.php?action=login
$roomId = isset($_GET['room_id']) ? (int)$_GET['room_id'] : 0;
$next   = $_GET['next'] ?? '';
?>
<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8">
  <title>Login - SAW</title>
  <link rel="stylesheet" href="/assets/css/style_public.css">
  <style>
    .auth-wrap{ max-width:420px; margin:36px auto; background:#fff; padding:20px; border-radius:10px; box-shadow:0 8px 24px rgba(2,6,23,0.06); }
    .auth-wrap h2{ margin:0 0 12px 0; }
    .form-row{ margin-bottom:12px; display:flex; flex-direction:column; gap:6px; }
    .form-row input{ padding:10px; border-radius:8px; border:1px solid #e6eef8; }
    .btn-login{ background:#0057b7; color:#fff; border:0; padding:10px 14px; border-radius:8px; cursor:pointer; width:100%; font-weight:600; }
    .small-link{ display:block; margin-top:8px; text-align:center; color:#475569; text-decoration:none; }
    .msg{ margin-top:10px; font-size:0.95rem; }

    /* Modal 2FA simples e centrado */
    .twofa-overlay{
      position:fixed; inset:0; background:rgba(15,23,42,0.45); display:none;
      align-items:center; justify-content:center; z-index:1500;
    }
    .twofa-card{
      background:#ffffff; border-radius:16px; padding:20px 22px 18px;
      max-width:420px; width:90%; box-shadow:0 18px 40px rgba(15,23,42,0.35);
      position:relative;
    }
    .twofa-close{
      position:absolute; top:8px; right:10px; border:0; background:transparent;
      font-size:18px; cursor:pointer; color:#6b7280;
    }
    .twofa-title{ margin:0 0 8px 0; font-size:1.25rem; font-weight:700; color:#0f172a; }
    .twofa-text{ margin:0 0 10px 0; font-size:0.9rem; color:#6b7280; }
    .twofa-code-input{
      letter-spacing:0.4em; text-align:center; font-size:1.2rem; padding:10px;
      border-radius:10px; border:1px solid #d1d5db; width:100%; box-sizing:border-box;
    }
  </style>
</head>
<body>
  <header class="topbar" role="navigation" aria-label="Navegação principal">
    <div class="logo">SAW — Sistema de Reservas</div>
    <nav class="nav" aria-label="Ações">
      <!-- Usa o roteador central index.php?page=... para não expor a estrutura interna -->
      <a class="ghost" href="/index.php?page=login">Login</a>
      <a class="primary" href="/index.php?page=register">Registar</a>
    </nav>
  </header>

  <main class="container" role="main">
    <div class="auth-wrap" aria-live="polite">
      <h2>Iniciar Sessão</h2>

      <?php if(!empty($_SESSION['flash_error'])): ?>
        <div class="msg" style="color:#9f1239;"><?php echo htmlspecialchars($_SESSION['flash_error']); unset($_SESSION['flash_error']); ?></div>
      <?php endif; ?>
      <?php if(!empty($_SESSION['flash_success'])): ?>
        <div class="msg" style="color:#065f46;"><?php echo htmlspecialchars($_SESSION['flash_success']); unset($_SESSION['flash_success']); ?></div>
      <?php endif; ?>

      <form id="loginForm">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
        <?php if($roomId > 0): ?>
          <input type="hidden" name="room_id" value="<?php echo $roomId; ?>">
        <?php endif; ?>
        <?php if($next !== ''): ?>
          <input type="hidden" name="next" value="<?php echo htmlspecialchars($next); ?>">
        <?php endif; ?>
        <div class="form-row">
          <label for="email">Email</label>
          <input id="email" type="email" name="email" required>
        </div>
        <div class="form-row">
          <label for="password">Senha</label>
          <input id="password" type="password" name="password" required>
        </div>
        <div class="form-row" style="flex-direction:row;align-items:center;justify-content:space-between;">
          <label style="font-size:0.95rem;"><input type="checkbox" name="remember"> Remember me</label>
          <div style="display:flex;flex-direction:column;align-items:flex-end;gap:2px;">
      <a class="small-link" href="/index.php?page=pedir_reset" style="margin:0;">Forgot me</a>
      <a class="small-link" href="/index.php?page=validar_conta" style="margin:0;font-size:0.85rem;">Validar conta</a>
      </div>
        </div>
        <div>
          <button class="btn-login" type="submit">Entrar</button>
        </div>
      </form>

      <a class="small-link" href="/index.php?page=register">Ainda não tem conta? Registe-se</a>

      <div id="loginMsg" class="msg" aria-atomic="true"></div>
    </div>
  </main>

  <!-- Modal 2FA -->
  <div id="twofaOverlay" class="twofa-overlay">
    <div class="twofa-card">
      <button type="button" id="twofaClose" class="twofa-close">×</button>
      <h3 class="twofa-title">Autenticação de dois fatores</h3>
      <p class="twofa-text">
        Confirme o acesso à sua conta introduzindo o código de 6 dígitos da sua app de autenticação.
      </p>
      <form id="twofaForm">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(\Security::csrf_token()); ?>">
        <input type="hidden" name="twofa_step" value="verify">
        <div class="form-row">
          <label for="twofa_code_modal">Código 2FA</label>
          <input id="twofa_code_modal" class="twofa-code-input" type="text" name="twofa_code"
                 maxlength="6" pattern="\d{6}" inputmode="numeric" required placeholder="••••••">
        </div>
        <button class="btn-login" type="submit">Confirmar código</button>
      </form>
    </div>
  </div>

<script>
(function(){
  var loginForm    = document.getElementById('loginForm');
  var twofaForm    = document.getElementById('twofaForm');
  var twofaOverlay = document.getElementById('twofaOverlay');
  var twofaClose   = document.getElementById('twofaClose');
  var msgEl        = document.getElementById('loginMsg');

  var roomField      = loginForm.querySelector('input[name="room_id"]');
  var pendingRoomId  = roomField ? (parseInt(roomField.value,10) || 0) : 0;

  function showMsg(text, color){
    if(!msgEl) return;
    msgEl.textContent = text || '';
    if(color) msgEl.style.color = color;
  }

  function openTwofaModal(){
    if(twofaOverlay){
      twofaOverlay.style.display = 'flex';
      var inp = document.getElementById('twofa_code_modal');
      if(inp) inp.focus();
    }
  }
  function closeTwofaModal(){
    if(twofaOverlay) twofaOverlay.style.display = 'none';
  }

  if(twofaClose){
    twofaClose.addEventListener('click', closeTwofaModal);
  }
  if(twofaOverlay){
    twofaOverlay.addEventListener('click', function(e){
      if(e.target === twofaOverlay) closeTwofaModal();
    });
  }

  function redirectAfterLogin(perfil){
    // se veio de uma sala pública, vai direto para reservar
    if(pendingRoomId > 0){
      window.location = '/index.php?page=user_reservar&sala_id=' + pendingRoomId;
      return;
    }
    var p = (perfil || '').toLowerCase();
    var dest = (p === 'admin') ? '/index.php?page=admin_dashboard' : '/index.php?page=user_rooms';
    window.location = dest;
  }

  function handleAuthResponse(json){
    if(!json){
      showMsg('Erro de autenticação', '#9f1239');
      return;
    }

    if(json.needs_2fa){
      showMsg('Introduza o código de 6 dígitos da app de autenticação.', '#065f46');
      openTwofaModal();
      return;
    }

    if(!json.ok){
      showMsg(json.msg || 'Erro de autenticação', '#9f1239');
      return;
    }

    // sucesso: json.perfil vem do servidor
    redirectAfterLogin(json.perfil || '');
  }

  // PASSO 1: enviar email + password
  loginForm.addEventListener('submit', function(e){
    e.preventDefault();
    var data = new FormData(loginForm);
    data.append('action','login');

    fetch('/index.php', { method:'POST', body:data, credentials:'include' })
      .then(function(resp){ return resp.json().catch(function(){ return null; }); })
      .then(handleAuthResponse)
      .catch(function(){
        showMsg('Erro de comunicação.', '#9f1239');
      });
  });

  // PASSO 2: enviar apenas o código 2FA
  twofaForm.addEventListener('submit', function(e){
    e.preventDefault();
    var data = new FormData(twofaForm);
    data.append('action','login');

    fetch('/index.php', { method:'POST', body:data, credentials:'include' })
      .then(function(resp){ return resp.json().catch(function(){ return null; }); })
      .then(function(json){
        if(json && json.ok) closeTwofaModal();
        handleAuthResponse(json);
      })
      .catch(function(){
        showMsg('Erro de comunicação.', '#9f1239');
      });
  });

  // AUTO-REDIRECT se já houver sessão criada pelo servidor (inclui remember-me)
  (function(){
    var isLogged = <?php echo !empty($_SESSION['user_id']) ? 'true' : 'false'; ?>;
    var perfil   = <?php echo json_encode($_SESSION['perfil'] ?? ''); ?>;
    if(isLogged){
      redirectAfterLogin(perfil);
    }
  })();
})();
</script>
</body>
</html>