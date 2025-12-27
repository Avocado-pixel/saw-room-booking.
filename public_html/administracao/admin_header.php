<?php
/**
 * Cabeçalho comum (barra superior) da área de administração.
 *
 * Este ficheiro é incluído pelo layout de administração e fornece:
 *   - o logotipo / título "SAW — Administração";
 *   - navegação principal para Salas, Utilizadores e Reservas;
 *   - um botão "Voltar" que usa o histórico do browser ou redireciona para
 *     o dashboard;
 *   - atalhos para o perfil do utilizador e para fazer logout.
 *
 * O JavaScript no fim trata apenas da navegação (botão voltar) e aplica uma
 * classe no <html> para que o CSS possa compensar a altura da barra fixa.
 */
?>
<header class="admin-topbar admin-topbar-fixed" role="navigation" aria-label="Admin navigation">
  <div class="topbar-left">
    <button type="button" class="btn-top back-btn" title="Voltar" aria-label="Voltar">←</button>
    <a class="admin-logo" href="/index.php?page=admin_dashboard" aria-label="Dashboard">
      <span class="mark" aria-hidden="true"></span>
      <span class="title">SAW — Administração</span>
    </a>
  </div>

  <nav class="topbar-nav" role="menubar" aria-label="Admin menu">
    <a class="nav-link" href="/index.php?page=admin_rooms" role="menuitem">Salas</a>
    <a class="nav-link" href="/index.php?page=admin_users" role="menuitem">Utilizadores</a>
    <a class="nav-link" href="/index.php?page=admin_reservas" role="menuitem">Reservas</a>
  </nav>

  <div class="topbar-actions">
    <a class="btn-top" href="/index.php?page=user_profile" title="Perfil">Perfil</a>
    <a class="btn-top primary" href="/index.php?action=logout" title="Logout">Logout</a>
  </div>
</header>

<script>
(function(){
  // comportamento do botão voltar: usa history se houver, senão vai para dashboard
  var back = document.querySelector('.admin-topbar .back-btn');
  if(back){
    back.addEventListener('click', function(){
      if(window.history.length > 1) window.history.back();
      else window.location = '/index.php?page=admin_dashboard';
    });
  }
  // marca o body para aplicar o espaçamento superior necessário
  try { document.documentElement.classList.add('admin-has-topbar'); } catch(e){}
})();
</script>
