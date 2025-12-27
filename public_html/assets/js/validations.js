// Valida NIF PT (algoritmo modulo 11) — mesma lógica do servidor (Validator::validateNIF_PT)
function validateNIF(nif){
	nif = (nif||'').replace(/\D/g,'');
	if(nif.length !== 9) return false;
	var sum = 0;
	for(var i=0;i<8;i++){
		sum += parseInt(nif.charAt(i),10) * (9 - i);
	}
	var remainder = sum % 11;
	var check = 11 - remainder;
	if(check >= 10) check = 0;
	return parseInt(nif.charAt(8),10) === check;
}

// Nome: pelo menos 2 palavras com 2+ letras, apenas letras/acentos/ - ' (espelha Validator::validateName)
function validateName(name){
	if(!name || name.trim().length < 4) return false;
	if(!/^[A-Za-zÀ-ÿ '\-]+$/.test(name)) return false;
	var parts = name.trim().split(/\s+/);
	var ok = 0;
	parts.forEach(function(p){ if(p.length>=2) ok++; });
	return ok >= 2;
}

// Email: validação simples de formato (lado cliente)
function validateEmailFormat(email){
	if(!email) return false;
	email = email.trim();
	return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
}

// Password forte (mínimo 10 caracteres, 1 maiúscula, 1 minúscula, 1 número, 1 símbolo)
// Alinhado com Validator::validatePasswordStrong no servidor
function validatePasswordStrong(pass){
	if(!pass || pass.length < 10) return false;
	if(!/[A-Z]/.test(pass)) return false;
	if(!/[a-z]/.test(pass)) return false;
	if(!/\d/.test(pass))   return false;
	if(!/[^A-Za-z0-9]/.test(pass)) return false;
	return true;
}

// Telemóvel: pelo menos 9 dígitos após remover tudo o que não é número (espelha regra em register.php)
function validatePhone(phone){
	if(!phone) return false;
	var digits = String(phone).replace(/\D/g,'');
	return digits.length >= 9;
}

// Morada: apenas verifica se não está vazia depois de trim (como no servidor)
function validateAddress(addr){
	return !!(addr && addr.trim().length > 0);
}

// Validação básica da foto de perfil no lado do cliente:
// - Obrigatória (para o registo).
// - Máx. 2MB.
// - Apenas JPEG/PNG (verifica tipo e extensão).
function validateProfileImageClient(file){
	var maxBytes = 2 * 1024 * 1024; // 2MB
	if(!file) return { ok:false, msg:'Selecione uma foto de perfil.' };
	if(file.size > maxBytes) return { ok:false, msg:'Foto demasiado grande (máx 2MB).' };
	var type = file.type || '';
	var name = file.name || '';
	var okType = (type === 'image/jpeg' || type === 'image/png');
	var okExt  = /\.(jpe?g|png)$/i.test(name);
	if(!(okType && okExt)){
		return { ok:false, msg:'Formato da imagem inválido. Apenas JPEG/PNG.' };
	}
	return { ok:true, msg:null };
}
