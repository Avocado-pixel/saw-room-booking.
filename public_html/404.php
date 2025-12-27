<?php
if(!isset($_SESSION)) session_start();
?>
<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8">
  <title>404 - Página não encontrada</title>
  <link rel="stylesheet" href="/assets/css/style_public.css">
  <style>
    .nf-wrap{
      max-width:520px;
      margin:80px auto;
      background:#fff;
      padding:24px;
      border-radius:12px;
      box-shadow:0 10px 30px rgba(15,23,42,0.12);
      text-align:center;
    }
    .nf-code{
      font-size:2.6rem;
      font-weight:800;
      color:#0f172a;
    }
    .nf-title{
      font-size:1.4rem;
      font-weight:700;
      margin:8px 0;
    }
    .nf-text{
      font-size:0.95rem;
      color:#6b7280;
      margin-bottom:16px;
    }
    .nf-actions button{
      display:inline-block;
      margin:4px 6px;
      padding:8px 14px;
      border-radius:8px;
      text-decoration:none;
      font-weight:600;
      font-size:0.95rem;
      border:0;
      background:#0057b7;
      color:#fff;
      cursor:pointer;
    }
  </style>
</head>
<body>
  <header class="topbar" role="navigation" aria-label="Navegação principal">
    <div class="logo">SAW — Sistema de Reservas</div>
    <nav class="nav" aria-label="Ações">
      <!-- ...sem links específicos aqui... -->
    </nav>
  </header>

  <main class="container" role="main">
    <div class="nf-wrap" aria-live="polite">
      <div class="nf-code">404</div>
      <div class="nf-title">Página não encontrada</div>
      <p class="nf-text">
        A página que procura não existe ou já não está disponível.<br>
        Verifique o endereço ou volte à página anterior.
      </p>
      <div class="nf-actions">
        <button type="button" id="btnBack">Voltar atrás</button>
      </div>
    </div>
  </main>

  <script>
    document.getElementById('btnBack').addEventListener('click', function () {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = '/index.php';
      }
    });
  </script>
</body>
</html>
