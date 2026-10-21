 O script comeca perguntando se voce deseja VERIFICAR o computador. A
    verificacao e somente leitura: procura processos, arquivos, pastas, tarefas
    agendadas, servicos, chaves de registro, regras de firewall, linhas do hosts,
    adaptador TAP e exclusoes do Defender ligados ao KMS Pico.

    - Se NADA for encontrado, exibe: "SEU COMPUTADOR NAO CONTEM ESTE MALWARE".
    - Se algo for encontrado, mostra a lista e pergunta se deseja REMOVER agora.

    Na remocao, cria ponto de restauracao antes de qualquer alteracao, limpa os
    vestigios, reseta a ativacao do Windows/Office para o estado legitimo e roda
    uma verificacao rapida do Windows Defender ao final.

    Tudo o que e feito aparece no console com o status de cada item:
    [ENCONTRADO]/[REMOVIDO] | [LIMPO]/[AUSENTE] | [PENDENTE] | [INFO].

    AVISO/ISENCAO: script criado para limpar e desativar o malware KMS Pico.
    O processo e seguro (ponto de restauracao + log no console), porem o uso e
    opcional e por sua conta e risco: nao nos responsabilizamos caso a
    desinstalacao traga problemas a ativacao do Office e do Windows, seja ela
    qualquer que seja a versao (OEM, Retail, Volume/KMS corporativo ou pirata).

    Uso 1 - Arquivo .ps1:
        powershell -NoProfile -ExecutionPolicy Bypass -File .\removeKMSPico.ps1

    Uso 2 - Arquivo salvo como .txt (quando o antivirus apaga o .ps1),
            PowerShell ABERTO COMO ADMINISTRADOR:
        iex (Get-Content "$env:USERPROFILE\Desktop\removeKMSPico.txt" -Raw)

    Uso 3 - Mesmo .txt, PowerShell NORMAL (o script pede UAC e relanca lendo
            o proprio .txt, sem criar nenhum .ps1 no disco):
        $env:KMS_SOURCE = "$env:USERPROFILE\Desktop\removeKMSPico.txt"
        iex (Get-Content $env:KMS_SOURCE -Raw)

    Parametro opcional (uso 1) / variavel de ambiente (usos 2 e 3):
        -SkipDefenderScan            Nao roda a verificacao rapida do Defender.
        $env:KMS_SKIP_SCAN = '1'     Equivalente via iex.

    Se nao for executado como Administrador, o script se auto-eleva via UAC.
    Via iex com $env:KMS_SOURCE definido, a janela elevada le o proprio .txt;
    sem KMS_SOURCE, ele tenta baixar o script do GitHub para o TEMP (ultimo
    recurso - o GitHub pode bloquear o arquivo).

    AVISO: em redes corporativas com servidor KMS legitimo (dominio/empresa),
    consulte o TI antes de executar - o script limpa configuracoes de canal KMS.
