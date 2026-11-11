import unittest

from simulation import extraction


class ExtractionTests(unittest.TestCase):
    def test_numeric_date_preserved_and_flagged_ambiguous(self):
        info = extraction.extract_datetime("meeting at 11/12/2009")
        self.assertEqual(info["selected_date"], "11/12/2009")
        self.assertTrue(info["ambiguous"])
        self.assertTrue(any("ambiguous" in n.lower() for n in info["notes"]))

    def test_numeric_date_with_trailing_period(self):
        self.assertEqual(extraction.extract_datetime("Meeting at 11/12/2009.")["selected_date"], "11/12/2009")

    def test_unambiguous_numeric_formats(self):
        self.assertFalse(extraction.extract_datetime("meeting on 25/12/2026")["ambiguous"])
        self.assertFalse(extraction.extract_datetime("meeting on 12/25/2026")["ambiguous"])
        self.assertFalse(extraction.extract_datetime("meeting on 11/11/2026")["ambiguous"])
        self.assertFalse(extraction.extract_datetime("meeting on 2026-11-12")["ambiguous"])

    def test_original_string_never_reformatted(self):
        self.assertEqual(extraction.extract_datetime("The call is on 5th of March, 2027.")["selected_date"], "5th of March, 2027")

    def test_named_dates_and_time(self):
        info = extraction.extract_datetime("Date: 25 October 2026\nTime: 3:30 PM")
        self.assertEqual((info["selected_date"], info["time"]), ("25 October 2026", "3:30 PM"))

    def test_meeting_date_preferred_over_deadline(self):
        info = extraction.extract_datetime("The project meeting is on 14 November at 10:00 AM. Please send your slides by 10 November.")
        self.assertEqual(info["selected_date"], "14 November")
        self.assertEqual(info["time"], "10:00 AM")
        self.assertIn("10 November", " ".join(info["notes"]))

    def test_missing_date(self):
        out = extraction.process("Tell me the meeting date.", "We will discuss the review soon.")
        self.assertIn("No meeting date", out["answer"])
        self.assertIsNone(out["extraction"]["selected_date"])

    def test_spanish_named_date(self):
        self.assertEqual(extraction.extract_datetime("La reunión será el 14 de noviembre a las 10:00.")["selected_date"], "14 de noviembre")

    def test_summary_is_extractive_and_respects_bullet_count(self):
        doc = "Hi team, the design review is on 22 October at 2 PM. Bring the updated diagrams. Please send questions by Wednesday."
        out = extraction.process("Summarize this email in three bullet points.", doc)
        self.assertEqual(len(out["summary"]), 3)
        self.assertIn("extractive", out["answer"])

    def test_date_and_summary_requested_together(self):
        out = extraction.process("Summarize this and give the meeting date.", "The meeting is on 14 November. Bring slides.")
        self.assertEqual(out["operations"], ["extract_datetime", "summarize"])


if __name__ == "__main__":
    unittest.main()
