# PKI-Lab Etapa 1 — emissor V3 standard para CAM/DENM

## Objetivo

Disponibilizar emissão local de uma cadeia ECC V3 no perfil ASN.1 standard,
sem depender de `certify-pqc` e sem modificar Vanetza ou ns-3.

## Perfil de autorização

| Nível | AID 36 CAM | AID 37 DENM |
|---|---:|---:|
| Root `certIssuePermissions` | Sim | Sim |
| AA `certIssuePermissions` | Sim | Sim |
| AT `appPermissions` | Sim | Sim |

A permissão em cada nível é explícita. A partilha do domínio `vehicle-v3` não
implica autorização automática de uma aplicação.

## Validade predefinida

Root: 365 dias. AA: 180 dias. AT: 30 dias. O início é definido uma hora antes
do instante de emissão para evitar uma janela de validade futura por causa da
precisão de segundos do campo temporal. O programa rejeita hierarquias em que
a validade do AA exceda a do Root ou a do AT exceda a do AA.

## Construção e assinatura

O código usa `Vanetza::security` do pacote instalado e `OpenSSL` explicitamente.
A assinatura primária segue a rotina de hashing e canonicalização já auditada:

`H( H(OER(canonical ToBeSignedCertificate)) || H(OER(canonical issuer certificate)) )`

Para Root autoassinado, a entrada OER do emissor é vazia. Para AA e AT, o
`HashedId8` do emissor fornecido tem de coincidir com `issuerIdentifier` antes
de assinar/verificar.

## Persistência

Cada execução gera uma nova pasta imutável em
`pki/domains/vehicle-v3/issuance/runs/`. A geração é criada numa pasta staging
privada e publicada por rename atómico no mesmo filesystem. Não existe opção
de sobrescrita. A geração contém cópias explícitas do trust anchor em
`trust-store/trusted-root.cert` e da cadeia AA → Root em `certificate-chain/`.
Chaves privadas são PKCS#8 PEM não cifradas, modo `0600`, dentro de diretórios
modo `0700`; a proteção depende também da segurança do host e dos backups.

## Critérios de aceitação ainda pendentes

1. Compilar com GCC 11 contra `/home/mmendes/opt/vanetza-cpm-gcc11`.
2. Executar o dry-run sem criar payloads.
3. Emitir uma cadeia controlada de um AT.
4. Revalidar Root, AA e AT com o verificador independente standard-profile já
   compilado durante a auditoria C-02.
5. Inspecionar as permissões e validade através do auditor de política.
6. Integrar os caminhos no runtime C-02 e demonstrar inicialização do signer.
7. Demonstrar CAM e DENM assinados; depois expandir para a frota.

A emissão local não significa aceitação em runtime. Trust store, cadeia
configurada, localização, revogação e comportamento real de assinatura
continuam a exigir evidência independente.
