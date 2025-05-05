import boto3


def apply_guardrail(text, text_type, region, guardrail_id, guardrail_version):
    """가드레일 적용 및 결과 분석"""
    try:
        client = boto3.client("bedrock-runtime", region_name=region)
        response = client.apply_guardrail(
            guardrailIdentifier=guardrail_id,
            guardrailVersion=guardrail_version,
            source=text_type,
            content=[{"text": {"text": text}}]
        )

        # 가드레일 위반 체크
        violations = []
        if response['action'] == 'GUARDRAIL_INTERVENED':
            for assessment in response.get('assessments', []):
                _check_violations(assessment, violations)

        # 필터링된 텍스트
        outputs = response.get('outputs', [])
        filtered_text = outputs[0].get('text', text) if outputs else text

        # 상태 결정
        if any(v['Action'] == 'BLOCKED' for v in violations):
            return "blocked", violations, filtered_text, response

        elif any(v['Action'] == 'ANONYMIZED' for v in violations):
            return "anonymized", violations, filtered_text, response

        else:
            return "passed", [], text, response

    except Exception as e:
        raise Exception(f"가드레일 적용 실패: {str(e)}")


def _check_violations(assessment, violations):
    """가드레일 위반 사항 체크"""
    # 토픽 정책
    if 'topicPolicy' in assessment:
        for topic in assessment['topicPolicy'].get('topics', []):
            violations.append({
                "Category": "Word filters",
                "Action": topic['action'],
                "Name": topic['name']
            })

    # 콘텐츠 정책
    if 'contentPolicy' in assessment:
        for filtered in assessment['contentPolicy'].get('filters', []):
            violations.append({
                "Category": "Content filters",
                "Action": filtered['action'],
                "Name": filtered['type']
            })

    # 민감 정보 정책
    if 'sensitiveInformationPolicy' in assessment:
        for regex in assessment['sensitiveInformationPolicy'].get('regexes', []):
            violations.append({
                "Category": "Regex filter",
                "Action": regex['action'],
                "Name": regex['name']
            })
        for pii in assessment['sensitiveInformationPolicy'].get('piiEntities', []):
            violations.append({
                "Category": "PII filter",
                "Action": pii['action'],
                "Name": pii['type']
            })

    # 단어 정책
    if 'wordPolicy' in assessment:
        for word in assessment['wordPolicy'].get('customWords', []):
            violations.append({
                "Category": "Custom word filters",
                "Action": word['action'],
                "Name": word['match']
            })
        for word in assessment['wordPolicy'].get('managedWordLists', []):
            violations.append({
                "Category": "Managed word filters",
                "Action": word['action'],
                "Name": word['match']
            })