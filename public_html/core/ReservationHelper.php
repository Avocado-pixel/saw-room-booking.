<?php
/**
 * Helpers para validar intervalos de reserva e verificar conflitos.
 */
class ReservationHelper {
    /**
     * Valida data/hora/duração e verifica conflitos na BD.
     * Retorna array: ['ok'=>bool,'error'=>?string,'inicio'=>?DateTime,'fim'=>?DateTime,'inicioSql'=>?string,'fimSql'=>?string]
     * Se $excludeId for fornecido exclui essa reserva na verificação de conflito (útil ao editar).
     */
    public static function validateInterval(PDO $pdo, string $data, string $hora, int $dur, int $salaId, ?int $excludeId = null): array {
        $data = trim($data);
        $hora = trim($hora);
        $dur  = (int)$dur;

        if(!preg_match('/^\d{4}-\d{2}-\d{2}$/',$data) || !preg_match('/^\d{2}:\d{2}$/',$hora)){
            return ['ok'=>false,'error'=>'Data ou hora inválida.'];
        }

        $inicioStr = $data.' '.$hora.':00';
        $inicio = DateTime::createFromFormat('Y-m-d H:i:s', $inicioStr);
        if(!$inicio) return ['ok'=>false,'error'=>'Data/hora inválidas.'];

        $agora = new DateTime('now');
        if($inicio < $agora) return ['ok'=>false,'error'=>'Não pode reservar para uma data/hora anterior à atual.'];

        $min = (int)$inicio->format('i');
        if($min % 30 !== 0) return ['ok'=>false,'error'=>'As reservas devem começar em blocos de 30 minutos (ex.: 09:00, 09:30).'];
        if($dur <= 0 || $dur % 30 !== 0) return ['ok'=>false,'error'=>'A duração deve ser múltiplo de 30 minutos.'];

        $fim = clone $inicio;
        $fim->modify('+'.$dur.' minutes');

        $inicioSql = $inicio->format('Y-m-d H:i:s');
        $fimSql    = $fim->format('Y-m-d H:i:s');

        // Verificar conflito (excluir $excludeId se existirem)
        $sql = "
            SELECT COUNT(*)
              FROM reservas
             WHERE sala_id = :sid
               AND data_inicio < :fim
               AND data_fim > :inicio
        ";
        if($excludeId !== null){
            $sql .= " AND id != :excl";
        }
        $st = $pdo->prepare($sql);
        $params = [':sid'=>$salaId, ':inicio'=>$inicioSql, ':fim'=>$fimSql];
        if($excludeId !== null) $params[':excl'] = (int)$excludeId;
        $st->execute($params);
        $existe = (int)$st->fetchColumn();
        if($existe > 0) return ['ok'=>false,'error'=>'Esta sala já está reservada nesse período. Escolha outra hora.'];

        return ['ok'=>true,'error'=>null,'inicio'=>$inicio,'fim'=>$fim,'inicioSql'=>$inicioSql,'fimSql'=>$fimSql];
    }
}
