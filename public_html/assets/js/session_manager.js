(function(){
	// Gestão simples de sessão no lado do cliente.
	// Não renova a sessão via AJAX nem mostra qualquer modal.
	// Apenas, ao fim de 20 minutos, faz logout automático
	// redirecionando para index.php?action=logout.

	var minutes = 20;
	var timerId;

	function start(){
		// Garante que não há múltiplos timeouts ativos
		clearTimeout(timerId);
		// Ao fim de 20 minutos na página, força logout no servidor
		timerId = setTimeout(onLogout, minutes * 60 * 1000);
	}

	function onLogout(){
		// Redireciona para a rota de logout no servidor
		// (routes/auth.php?action=logout), que destrói a sessão
		// e envia o utilizador para as salas públicas.
		window.location = 'index.php?action=logout';
	}

	// Inicia o contador logo que o script é carregado.
	start();
})();
