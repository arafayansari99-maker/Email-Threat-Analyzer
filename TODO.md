# TODO — Attachment text extraction + full suspicious word matching

## Step 1 (High-impact): Extract attachment text into parsed result
- [ ] Update `eta/backend/analysis_engine.py` `parse_email_bytes()` to create `result['attachment_text'] = ''`
- [ ] During multipart walk, decode each attachment payload and call `_extract_text_from_file(payload, filename)`
- [ ] Append extracted text into `result['attachment_text']`

## Step 2: Run `analyze_keywords()` over subject + body_text + body_html + attachment_text
- [ ] Update `eta/backend/analysis_engine.py` `extract_ml_features()` to include `parsed['attachment_text']`

## Step 3 (Optional): Return full match lists / by_category
- [ ] Update `classify_phishing()` output to include uncapped match lists and `by_category`

## Step 4 (Optional): Broaden extraction to inline extractable parts
- [ ] Update attachment detection logic to include `inline`/`application/*` where appropriate

## Step 5: Validate with existing test emails
- [ ] Run quick test / verify output on `eta/test_emails/*.eml`

