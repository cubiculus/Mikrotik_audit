"""Template-based explanations for firewall conflicts.

This module provides detailed, user-friendly explanations for each type
of conflict detected by ConflictAnalyzer. Each explanation includes:
- What's happening (2-3 sentences)
- Why it's a problem
- How to fix it with specific RouterOS commands
- Potential side effects to watch for
"""

from typing import Dict, List
from dataclasses import dataclass
from src.conflict_analyzer import ConflictType, ConflictResult


@dataclass
class ConflictExplanation:
    """Detailed explanation template for a conflict type."""

    title: str
    what_is_happening: str
    why_problematic: str
    how_to_fix: List[str]
    side_effects: str
    references: List[str]


# Template explanations for each conflict type
CONFLICT_TEMPLATES: Dict[ConflictType, ConflictExplanation] = {

    ConflictType.UNREACHABLE_RULE: ConflictExplanation(
        title="Недостижимое правило фаервола",

        what_is_happening=(
            "Правило фаервола никогда не сработает, потому что оно расположено после "
            "более общего правила (catch-all), которое перехватывает весь трафик. "
            "В RouterOS правила обрабатываются последовательно сверху вниз, и первое "
            "совпавшее правило применяется."
        ),

        why_problematic=(
            "Это приводит к тому, что правило становится мёртвым кодом — оно не влияет "
            "на трафик, но создаёт ложное ощущение защиты. Например, правило drop после "
            "правила accept для всех никогда не сработает."
        ),

        how_to_fix=[
            "# 1. Найдите проблемное правило:",
            "/ip firewall filter print detail where numbers=PROBLEM_RULE_NUM",
            "",
            "# 2. Найдите catch-all правило перед ним:",
            "/ip firewall filter print detail where numbers=CATCH_ALL_NUM",
            "",
            "# 3. Переместите специфичное правило ПЕРЕД общим:",
            "/ip firewall filter move numbers=PROBLEM_RULE_NUM before=CATCH_ALL_NUM",
            "",
            "# 4. Или удалите недостижимое правило если оно не нужно:",
            "/ip firewall filter remove [find where numbers=PROBLEM_RULE_NUM]"
        ],

        side_effects=(
            "При перемещении правил убедитесь, что новый порядок не нарушает другую "
            "логику фаервола. Всегда тестируйте изменения в нерабочее время."
        ),

        references=[
            "https://help.mikrotik.com/docs/display/ROS/Packet+Flow",
            "https://wiki.mikrotik.com/wiki/Manual:Packet_Flow"
        ]
    ),

    ConflictType.NAT_BYPASSES_FIREWALL: ConflictExplanation(
        title="NAT обходит фаервол",

        what_is_happening=(
            "Правило dstnat перенаправляет входящий трафик на внутренний хост, но "
            "в chain=forward нет соответствующего правила, разрешающего этот трафик. "
            "В RouterOS NAT (dstnat) применяется ДО firewall forward chain."
        ),

        why_problematic=(
            "Трафик может достичь внутреннего хоста даже если firewall forward chain "
            "настроен на блокировку. Это создаёт брешь в безопасности — злоумышленник "
            "может использовать NAT для обхода фаервола."
        ),

        how_to_fix=[
            "# 1. Добавьте правило для established соединений:",
            "/ip firewall filter add chain=forward dst-address=DEST_IP "
            "connection-state=established,related action=accept "
            "comment=\"Allow established to NAT host\"",
            "",
            "# 2. Добавьте явные правила для сервисов:",
            "/ip firewall filter add chain=forward dst-address=DEST_IP "
            "protocol=tcp dst-port=80 action=accept comment=\"Allow HTTP\"",
            "/ip firewall filter add chain=forward dst-address=DEST_IP "
            "protocol=tcp dst-port=443 action=accept comment=\"Allow HTTPS\"",
            "",
            "# 3. Заблокируйте остальной трафик:",
            "/ip firewall filter add chain=forward dst-address=DEST_IP "
            "action=drop comment=\"Block other traffic to NAT host\""
        ],

        side_effects=(
            "Добавление разрешающих правил может открыть доступ к сервисам, которые "
            "должны оставаться закрытыми. Проверьте какие сервисы работают на хосте."
        ),

        references=[
            "https://help.mikrotik.com/docs/display/ROS/Source+NAT",
            "https://help.mikrotik.com/docs/display/ROS/Destination+NAT"
        ]
    ),

    ConflictType.ORPHAN_ROUTING_MARK: ConflictExplanation(
        title="Маркировка маршрута без маршрута",

        what_is_happening=(
            "Mangle правило помечает трафик routing-mark, но в таблице маршрутизации "
            "нет маршрута с этой меткой. Помеченный трафик будет использовать маршрут "
            "по умолчанию вместо предполагаемого пути."
        ),

        why_problematic=(
            "Трафик идёт не через тот интерфейс (например, не через VPN туннель, "
            "а через основной канал). Это может привести к утечке трафика или "
            "неправильной маршрутизации."
        ),

        how_to_fix=[
            "# 1. Проверьте mangle правило:",
            "/ip firewall mangle print detail where routing-mark=MARK_NAME",
            "",
            "# 2. Добавьте маршрут с этой меткой:",
            "/ip route add dst-address=DESTINATION routing-mark=MARK_NAME "
            "gateway=GATEWAY_IP distance=1 comment=\"Route for MARK_NAME\"",
            "",
            "# 3. Или удалите маркировку если не нужна:",
            "/ip firewall mangle disable [find where routing-mark=MARK_NAME]",
            "/ip firewall mangle remove [find where routing-mark=MARK_NAME]"
        ],

        side_effects=(
            "Добавление маршрута может изменить путь трафика для других сервисов. "
            "Убедитесь что gateway доступен и маршрут не создаст петлю."
        ),

        references=[
            "https://help.mikrotik.com/docs/display/ROS/Mangle",
            "https://help.mikrotik.com/docs/display/ROS/Policy+Based+Routing"
        ]
    ),

    ConflictType.INTERFACE_NOT_IN_LIST: ConflictExplanation(
        title="Интерфейс не в списке WAN/LAN",

        what_is_happening=(
            "Интерфейс существует и активен (имеет IP адрес), но не добавлен ни в "
            "один из списков интерфейсов (WAN или LAN). Правила фаервола, которые "
            "используют эти списки, не будут применяться к этому интерфейсу."
        ),

        why_problematic=(
            "Трафик через этот интерфейс может проходить без проверки фаерволом. "
            "Например, если правило блокирует WAN→LAN но интерфейс не в списке WAN, "
            "блокировка не сработает."
        ),

        how_to_fix=[
            "# 1. Определите назначение интерфейса:",
            "/interface print where name=INTERFACE_NAME",
            "/ip address print where interface=INTERFACE_NAME",
            "",
            "# 2. Добавьте в WAN список (если внешний интерфейс):",
            "/interface list member add interface=INTERFACE_NAME list=WAN",
            "",
            "# 3. Или добавьте в LAN список (если внутренний):",
            "/interface list member add interface=INTERFACE_NAME list=LAN",
            "",
            "# 4. Проверьте что правило добавлено:",
            "/interface list member print where interface=INTERFACE_NAME"
        ],

        side_effects=(
            "Добавление интерфейса в WAN список может немедленно применить правила "
            "блокировки. Убедитесь что у вас есть альтернативный доступ к роутеру."
        ),

        references=[
            "https://help.mikrotik.com/docs/display/ROS/Interface+Lists"
        ]
    ),

    ConflictType.ADDRESS_LIST_CONFLICT: ConflictExplanation(
        title="Конфликт списков адресов",

        what_is_happening=(
            "Один и тот же IP адрес присутствует одновременно в разрешающем (allow) "
            "и запрещающем (block) списке адресов. Поведение фаервола зависит от "
            "порядка правил, что делает конфигурацию непредсказуемой."
        ),

        why_problematic=(
            "При изменении порядка правил или добавлении новых правил трафик может "
            "неожиданно блокироваться или разрешаться. Это создаёт трудности в "
            "отладке и потенциальные бреши безопасности."
        ),

        how_to_fix=[
            "# 1. Найдите все вхождения адреса:",
            "/ip firewall address-list print where address=IP_ADDRESS",
            "",
            "# 2. Определите какой список правильный:",
            "# Если адрес должен быть разрешён - удалите из block:",
            "/ip firewall address-list remove [find where list~\"block\" address=IP_ADDRESS]",
            "",
            "# Если адрес должен быть заблокирован - удалите из allow:",
            "/ip firewall address-list remove [find where list~\"allow\" address=IP_ADDRESS]",
            "",
            "# 3. Проверьте результат:",
            "/ip firewall address-list print where address=IP_ADDRESS"
        ],

        side_effects=(
            "Удаление адреса из списка может немедленно изменить доступность сервиса. "
            "Убедитесь что изменение соответствует политике безопасности."
        ),

        references=[
            "https://help.mikrotik.com/docs/display/ROS/Address+Lists"
        ]
    ),

    ConflictType.FORWARD_WITHOUT_FASTTRACK: ConflictExplanation(
        title="Отсутствует правило FastTrack",

        what_is_happening=(
            "В конфигурации много правил в chain=forward, но нет правила fasttrack-connection. "
            "FastTrack позволяет роутеру обходить полную обработку пакетов для "
            "established соединений, значительно повышая производительность."
        ),

        why_problematic=(
            "Без FastTrack каждый пакет проходит полную проверку через все правила "
            "фаервола. На загруженных каналах это может снизить производительность "
            "на 30-50% и увеличить задержки."
        ),

        how_to_fix=[
            "# 1. Добавьте FastTrack правило (должно быть первым в chain):",
            "/ip firewall filter add chain=forward action=fasttrack-connection "
            "connection-state=established,related comment=\"FastTrack\" place-before=0",
            "",
            "# 2. Убедитесь что established соединения разрешены:",
            "/ip firewall filter add chain=forward action=accept "
            "connection-state=established,related comment=\"Allow established\"",
            "",
            "# 3. Проверьте порядок правил:",
            "/ip firewall filter print"
        ],

        side_effects=(
            "FastTrack не работает с некоторыми функциями (queue simple, certain "
            "mangle rules). Если используете эти функции, пакеты не будут fasttracked."
        ),

        references=[
            "https://help.mikrotik.com/docs/display/ROS/FastTrack"
        ]
    ),

    ConflictType.SHADOWED_RULE: ConflictExplanation(
        title="Правило перекрыто другим правилом",

        what_is_happening=(
            "Правило фаервола полностью перекрыто более общим правилом, которое "
            "расположено выше в списке. Более общее правило совпадает со всем "
            "трафиком, который совпал бы с этим правилом."
        ),

        why_problematic=(
            "Правило никогда не сработает и является мёртвым кодом. Это усложняет "
            "понимание конфигурации и может создать ложное ощущение защиты."
        ),

        how_to_fix=[
            "# 1. Изучите оба правила:",
            "/ip firewall filter print detail where numbers=SHADOWED_NUM",
            "/ip firewall filter print detail where numbers=SHADOWING_NUM",
            "",
            "# 2. Если специфичное правило нужно - переместите его выше:",
            "/ip firewall filter move numbers=SHADOWED_NUM before=SHADOWING_NUM",
            "",
            "# 3. Или удалите дублирующееся правило:",
            "/ip firewall filter remove [find where numbers=SHADOWED_NUM]"
        ],

        side_effects=(
            "Изменение порядка правил может повлиять на другой трафик. Тщательно "
            "протестируйте после изменений."
        ),

        references=[
            "https://help.mikrotik.com/docs/display/ROS/Filter"
        ]
    ),

    ConflictType.DUPLICATE_RULE: ConflictExplanation(
        title="Дублирующееся правило фаервола",

        what_is_happening=(
            "Два или более правила фаервола имеют идентичные параметры (chain, action, "
            "addresses, ports, protocols). Второе правило никогда не сработает, так "
            "как трафик будет обработан первым."
        ),

        why_problematic=(
            "Дубликаты увеличивают размер конфигурации без пользы, замедляют обработку "
            "пакетов и усложняют понимание правил фаервола."
        ),

        how_to_fix=[
            "# 1. Найдите дубликаты:",
            "/ip firewall filter print detail where numbers=FIRST_NUM",
            "/ip firewall filter print detail where numbers=DUPLICATE_NUM",
            "",
            "# 2. Удалите дублирующееся правило:",
            "/ip firewall filter remove [find where numbers=DUPLICATE_NUM]",
            "",
            "# 3. Проверьте что осталось одно правило:",
            "/ip firewall filter print where chain=CHAIN_NAME"
        ],

        side_effects=(
            "Удаление дубликата безопасно — трафик будет обрабатываться так же, "
            "как и раньше (первым правилом)."
        ),

        references=[
            "https://help.mikrotik.com/docs/display/ROS/Filter"
        ]
    )
}


def get_explanation(conflict: ConflictResult) -> ConflictExplanation:
    """
    Get detailed explanation for a conflict.

    Args:
        conflict: Conflict result from ConflictAnalyzer

    Returns:
        ConflictExplanation with detailed templates
    """
    template = CONFLICT_TEMPLATES.get(conflict.conflict_type)

    if template is None:
        # Return generic explanation for unknown conflict types
        return ConflictExplanation(
            title=f"Conflict: {conflict.conflict_type.value}",
            what_is_happening=conflict.description,
            why_problematic="This configuration may cause unexpected behavior.",
            how_to_fix=conflict.fix_commands or ["# Review configuration"],
            side_effects="Review changes carefully before applying.",
            references=[]
        )

    return template


def format_explanation_for_report(conflict: ConflictResult) -> str:
    """
    Format conflict explanation for HTML/text report.

    Args:
        conflict: Conflict result

    Returns:
        Formatted explanation string
    """
    explanation = get_explanation(conflict)

    lines = [
        f"<h3>{explanation.title}</h3>",
        f"<p><strong>Проблема:</strong> {explanation.what_is_happening}</p>",
        f"<p><strong>Почему это проблема:</strong> {explanation.why_problematic}</p>",
        "<p><strong>Как исправить:</strong></p>",
        "<pre><code>"
    ]

    lines.extend(explanation.how_to_fix)

    lines.extend([
        "</code></pre>",
        f"<p><strong>Возможные побочные эффекты:</strong> {explanation.side_effects}</p>"
    ])

    if explanation.references:
        lines.append("<p><strong>Ссылки:</strong></p><ul>")
        for ref in explanation.references:
            lines.append(f"<li><a href=\"{ref}\" target=\"_blank\">{ref}</a></li>")
        lines.append("</ul>")

    return "\n".join(lines)


def get_all_conflict_types() -> List[ConflictType]:
    """Return list of all conflict types with explanations."""
    return list(CONFLICT_TEMPLATES.keys())
