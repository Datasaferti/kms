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
