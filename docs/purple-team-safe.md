# Purple Team Seguro

O Purple Team neste projeto é uma prática de **validação defensiva**: uma simulação benigna reproduz apenas a telemetria necessária para provar ou refutar uma hipótese de detecção. Não é um repositório de exploração, payloads, evasão ou coleta de credenciais.

## Como ele se conecta ao detection-as-code

```mermaid
flowchart LR
  H[Hipótese de detecção] --> S[Simulação benigna em VM isolada]
  S --> T[Telemetria esperada]
  T --> W[Alerta e evidência no Wazuh]
  W --> R[Atualizar regra, teste ou tuning]
  R --> Q[Quality gate e revisão]
```

Cada item do catálogo já possui uma simulação em `simulations/windows/`. A evolução agora é registrar cada execução em um artefato de evidência, sem enviar logs de clientes ou dados sensíveis ao Git.

## Contrato de validação

Todo exercício deve declarar:

1. **Hipótese** — o comportamento e a regra que devem produzir alerta.
2. **Ambiente** — VM isolada, autorizada e descartável; fonte de telemetria habilitada.
3. **Ação benigna** — comando ou fixture que não baixa, explora ou persiste código externo.
4. **Telemetria esperada** — provedor, Event ID e campos a confirmar.
5. **Evidência Wazuh** — rule ID, técnica MITRE, timestamp e correlação do alerta.
6. **Resultado** — detectado, não detectado ou requer tuning.
7. **Limpeza** — remoção explícita de qualquer artefato temporário.

## Limites inegociáveis

- Sem exploração de vulnerabilidades, shell reverso, malware ou credenciais reais.
- Sem execução em produção ou endpoints compartilhados.
- Sem commits de logs brutos, IPs internos, usuários, tokens ou evidências sensíveis.
- Sem considerar um teste de fixture como validação operacional: a confirmação no Wazuh deve ocorrer em VM autorizada.

## Ciclo de evidência

Use o modelo em `simulations/validation-record-template.md` para cada execução. Salve apenas uma versão higienizada — sem identificadores de ambiente — em uma issue privada, ferramenta de tickets ou diretório interno de evidências. O repositório mantém o procedimento e o contrato, não dados operacionais.
