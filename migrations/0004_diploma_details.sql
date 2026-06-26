-- Richer, real-world diploma data: holder personal details + the MEC diploma
-- registry block (número de registro / livro / folha). Columns are nullable so
-- the migration applies cleanly to a populated table; the seed fills them in.

ALTER TABLE students
    ADD COLUMN national_id     TEXT,   -- CPF (Brazilian taxpayer / national id)
    ADD COLUMN nationality     TEXT,   -- e.g. "Brasileira"
    ADD COLUMN birthplace      TEXT,   -- naturalidade, "Cidade, UF"
    ADD COLUMN graduation_date DATE,   -- data de colação de grau
    ADD COLUMN registry_number TEXT,   -- número de registro do diploma
    ADD COLUMN registry_book   TEXT,   -- livro de registro
    ADD COLUMN registry_page   TEXT;   -- folha
