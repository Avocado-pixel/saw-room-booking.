<?php
/**
 * Listagem pública de salas disponíveis para reserva.
 *
 * Objetivo:
 * - Mostrar a qualquer visitante (mesmo não autenticado) as salas ativas,
 *   com paginação e pequeno campo de pesquisa por nome.
 * - Permitir que o visitante siga para o login já com a sala escolhida,
 *   usando parâmetros na query string para pré-preencher a navegação.
 *
 * Funcionamento técnico:
 * - Usa Paginator para limitar a 6 salas por página e construir links/queries.
 * - Lê apenas salas com estado_registo != 'eliminado' e estado = 'disponivel'.
 * - Se houver pesquisa (?q=...), adiciona condição "nome LIKE :q".
 * - As fotos são servidas através de room_image.php, que protege contra path traversal.
 * - O botão "Reservar" envia o utilizador para o login (index.php?page=login),
 *   passando room_id e next, sem expor diretamente rotas internas.
 */

if(!isset($pdo)) require_once __DIR__ . '/../bootstrap.php';

// ------------------------------
// Paginação + pesquisa de salas públicas
// ------------------------------
$params = [];
$sqlBase = "FROM salas WHERE estado_registo != 'eliminado' AND estado = 'disponivel'";

$p = new Paginator($_GET, 6); // 6 salas por página

if($p->hasSearch()){
	$sqlBase .= " AND nome LIKE :q";
	$params[':q'] = '%'.$p->getSearch().'%';
}

// contar total
$stCount = $pdo->prepare("SELECT COUNT(*) ".$sqlBase);
$stCount->execute($params);
$p->setTotal((int)$stCount->fetchColumn());

// buscar salas desta página
$sqlList = "SELECT id,nome,capacidade,foto ".$sqlBase." ORDER BY nome ".$p->limitSql();
$st = $pdo->prepare($sqlList);
$st->execute($params);
$salas = $st->fetchAll(PDO::FETCH_ASSOC);
?>
<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8">
  <title>Salas Disponíveis</title>
  <!-- style_public é injetado automaticamente pelo render_view_with_public_css;
       mantive link explícito por compatibilidade opcional -->
  <link rel="stylesheet" href="/assets/css/style_public.css">
</head>
<body>
  <!-- Topbar com links para Login / Registar -->
  <header class="topbar" role="navigation" aria-label="Navegação principal">
    <div class="logo">SAW — Sistema de Reservas</div>
    <nav class="nav" aria-label="Ações">
    <!-- Usa o roteador central index.php?page=... para não expor a estrutura interna -->
    <a class="ghost" href="/index.php?page=login">Login</a>
    <a class="primary" href="/index.php?page=register">Registar</a>
	</nav>
  </header>

  <main class="container" role="main">
    <section style="max-width:1000px;margin:32px auto;padding:0 16px;">
      <h1 style="margin:0 0 12px 0;font-size:1.7rem;">Salas</h1>
      

      <!-- barra de pesquisa -->
      <?php echo $p->renderSearchForm('Procurar sala...', 'q'); ?>

      <?php if(empty($salas)): ?>
        <p style="font-size:0.95rem;color:#6b7280;">Nenhuma sala encontrada.</p>
      <?php else: ?>
        <div
          style="
            display:grid;
            grid-template-columns:repeat(3, minmax(0, 1fr)); /* força 3 por linha em desktop */
            gap:14px;
            align-items:stretch;
          "
        >
          <?php foreach($salas as $s): ?>
            <?php
              $foto = !empty($s['foto']) ? '/room_image.php?file='.rawurlencode($s['foto']) : null;
              $roomId = (int)$s['id'];
              // next opcional: após login podes usar isto para redirecionar à página de reserva
              $next = urlencode('/index.php?page=user_rooms&room_id='.$roomId);
            ?>
            <article
              style="
                background:#ffffff;
                border-radius:10px;
                border:1px solid #e5e7eb;
                box-shadow:0 4px 16px rgba(15,23,42,0.06);
                display:flex;
                flex-direction:column;
                overflow:hidden;
                min-height:260px;
              "
            >
              <?php if($foto): ?>
                <div style="height:120px;background:#e5e7eb;overflow:hidden;">
                  <img src="<?php echo $foto; ?>" alt="Foto da sala"
                       style="width:100%;height:100%;object-fit:cover;">
                </div>
              <?php endif; ?>

              <div style="padding:10px 12px;display:flex;flex-direction:column;gap:6px;flex:1;">
                <h2 style="margin:0;font-size:1.02rem;"><?php echo htmlspecialchars($s['nome']); ?></h2>
                <div style="font-size:0.9rem;color:#6b7280;">
                  Capacidade: <strong><?php echo (int)$s['capacidade']; ?></strong> pessoas
                </div>
                <div style="margin-top:auto;">
                  <a href="/index.php?page=login&room_id=<?php echo $roomId; ?>&next=<?php echo $next; ?>"
                     style="
                       display:inline-block;
                       padding:6px 12px;
                       border-radius:8px;
                       background:#0057b7;
                       color:#fff;
                       text-decoration:none;
                       font-weight:600;
                       font-size:0.9rem;
                     ">
                    Reservar
                  </a>
                </div>
              </div>
            </article>
          <?php endforeach; ?>
        </div>

        <!-- links de paginação -->
        <?php echo $p->renderLinks('p'); ?>
      <?php endif; ?>
    </section>
  </main>

</body>
</html>