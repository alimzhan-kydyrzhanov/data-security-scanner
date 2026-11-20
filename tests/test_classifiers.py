from dsscan.classifiers import HIGH, MEDIUM, classify, czech_birth_number_ok, iban_ok, kz_iin_ok, luhn_ok
from dsscan.labels import apply_label, recommend_label


def test_checksums():
    assert luhn_ok("4111 1111 1111 1111")
    assert not luhn_ok("4111 1111 1111 1112")
    assert iban_ok("CZ65 0800 0000 1920 0014 5399")
    assert not iban_ok("CZ00 0800 0000 1920 0014 5399")
    assert czech_birth_number_ok("736028/5163")  # woman (month + 50)
    assert not czech_birth_number_ok("736028/5164")
    assert not czech_birth_number_ok("991340/0000")  # month 13 does not exist


def test_kz_iin():
    from scripts.generate_data import kz_iin
    assert kz_iin_ok(kz_iin())
    assert not kz_iin_ok("123456789012")


def test_keyword_raises_confidence():
    with_kw = classify("payment card 4111 1111 1111 1111")
    without = classify("ref 4111 1111 1111 1111")
    assert with_kw.matches[0].confidence == HIGH
    assert without.matches[0].confidence == MEDIUM


def test_icd_needs_supporting_keyword():
    assert classify("room J45 is free").counts() == {}
    assert classify("diagnosis: J45.0").counts() == {"ICD-10 Diagnosis Code": 1}


def test_card_digits_inside_iban_not_double_counted():
    assert classify("IBAN CZ65 0800 0000 1920 0014 5399").counts() == {"IBAN": 1}


def test_labels():
    health = classify("patient birth number 736028/5163, diagnosis: E11.9, email a@b.cz")
    assert recommend_label(health)[0] == "Highly Confidential"
    assert recommend_label(classify("tel +420 735 111 222"))[0] == "Internal"
    assert recommend_label(classify("Breakfast 7-10"))[0] == "Public"


def test_auto_label_never_downgrades():
    assert apply_label("Highly Confidential", "Internal") == "Highly Confidential"
    assert apply_label(None, "Confidential") == "Confidential"
    assert apply_label("Internal", "Confidential") == "Confidential"
