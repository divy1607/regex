import json
import re
import os
import glob
import pandas as pd
from collections import defaultdict
import yaml
from pathlib import Path


class CallAnalyzer:

    def __init__(self):
        self.profanity_list = {
            "damn", "hell", "shit", "fuck", "ass", "bitch", "crap", "piss",
            "dick", "bastard", "asshole", "bullshit", "cunt", "goddamn"
        }

        self.sensitive_patterns = {
            "SSN": re.compile(r'\b\d{3}[-]?\d{2}[-]?\d{4}\b'),
            "DOB": re.compile(r'\b(0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12][0-9]|3[01])[\/\-](19|20)?\d{2}\b'),
            "Account": re.compile(r'\baccount\s?(?:number|#|no)?\s?[:#]?\s?\d{4,}\b'),
            "Balance": re.compile(r'\b(?:balance|amount|owe|debt).{0,20}\$?\s?\d+(?:\.\d{2})?\b'),
            "Address": re.compile(r'\b\d+\s+([A-Za-z]+\s?)+,?\s*([A-Za-z]+\s?)+,?\s*[A-Z]{2}\s*\d{5}(-\d{4})?\b'),
            "Credit Card": re.compile(r'\b(?:\d{4}[ -]?){3}\d{4}\b'),
            "Phone": re.compile(r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b')
        }

        self.verification_patterns = {
            "DOB_verification": re.compile(r'\b(?:date\s+of\s+birth|dob|birthday).{0,30}(?:verify|confirm|check)'),
            "Address_verification": re.compile(r'\b(?:address|residence).{0,30}(?:verify|confirm|check)'),
            "SSN_verification": re.compile(r'\b(?:ssn|social security|social).{0,30}(?:verify|confirm|check)')
        }

        self.results = {}

    def detect_profanity(self, text):
        """Detect profanity in text"""
        text = str(text).lower()
        words = re.findall(r'\b\w+\b', text)
        return [word for word in words if word in self.profanity_list]

    def detect_sensitive_info(self, text):
        """Detect sensitive information in text"""
        text = str(text).lower()
        violations = {label: pattern.findall(text) for label, pattern in self.sensitive_patterns.items() if pattern.search(text)}
        return violations if violations else None

    def detect_verification(self, conversation):
        """Check if verification was performed before sensitive info was shared"""
        verification_done = {key: False for key in self.verification_patterns.keys()}
        sensitive_info_shared = False

        for entry in conversation:
            if entry["speaker"].lower() == "agent":
                text = entry["text"].lower()

                for key, pattern in self.verification_patterns.items():
                    if pattern.search(text):
                        verification_done[key] = True  # Mark verification done

        return verification_done  # Return full verification state

    def analyze_silence_overtalk(self, conversation):

        """Calculate silence and overtalk metrics using a sweep-line algorithm"""
        if not conversation:
            return {"silence_pct": 0, "overtalk_pct": 0}

        stimes = [entry["stime"] for entry in conversation]
        etimes = [entry["etime"] for entry in conversation]
        first_time, last_time = min(stimes), max(etimes)
        total_duration = last_time - first_time

        if total_duration <= 0:
            return {"silence_pct": 0, "overtalk_pct": 0}

        silence_duration = 0
        last_end = first_time

        for entry in sorted(conversation, key=lambda x: x["stime"]):
            if entry["stime"] > last_end:
                silence_duration += (entry["stime"] - last_end)
            last_end = max(last_end, entry["etime"])

        events = []
        for entry in conversation:
            events.append((entry["stime"], 1))  # Start of speech
            events.append((entry["etime"], -1))  # End of speech

        events.sort()
        concurrent_speakers, overtalk_duration = 0, 0
        prev_time = first_time

        for time, change in events: 
            if concurrent_speakers > 1:
                overtalk_duration += (time - prev_time)
            concurrent_speakers += change
            prev_time = time

        return {
            "total_call_duration": total_duration,
            "silence_duration": silence_duration,
            "silence_pct": (silence_duration / total_duration) * 100,
            "overtalk_duration": overtalk_duration,
            "overtalk_pct": (overtalk_duration / total_duration) * 100
        }

    def analyze_call(self, conversation, call_id):
        """Analyze a single call"""
    
        start_time = min(entry["stime"] for entry in conversation)
        end_time = max(entry["etime"] for entry in conversation)
        total_duration = end_time - start_time

        verification_state = self.detect_verification(conversation)

        result = {
            "call_id": call_id,
            "profanity": {"agent": [], "customer": []},
            "privacy_compliance": {
                "verification_done": any(verification_state.values()),
                "sensitive_info_shared": False,
                "violations": []
            },
            "call_metrics": self.analyze_silence_overtalk(conversation),
            "total_duration": total_duration  # Show call duration correctly
        }

        for entry in conversation:
            speaker = entry["speaker"].lower()
            text = entry["text"]

            if isinstance(text, str):
                profanity = self.detect_profanity(text)
                if profanity:
                    result["profanity"][speaker].append({"text": text, "profanity": profanity})

                if speaker == "agent":
                    sensitive = self.detect_sensitive_info(text)
                    if sensitive:
                        result["privacy_compliance"]["sensitive_info_shared"] = True

                        for key, detected in sensitive.items():
                            if not verification_state.get(f"{key}_verification", False):
                                result["privacy_compliance"]["violations"].append({
                                    "text": text,
                                    "sensitive_info": detected,
                                    "missing_verification": key
                                })

        return result

    def analyze_calls_from_json_directory(self, directory):
        """Analyze all JSON call records in a directory"""
        results = {}
        directory = Path(directory)
        json_files = directory.glob("*.json")

        for json_file in json_files:
            try:
                with open(json_file, 'r') as file:
                    conversation = json.load(file)
                call_id = json_file.stem
                results[call_id] = self.analyze_call(conversation, call_id)
            except json.JSONDecodeError:
                print(f"Skipping corrupted file: {json_file}")

        self.results = results
        return results

    def export_results_to_csv(self, output_file):
        """Export results to CSV"""
        df = pd.DataFrame([
            {
                "call_id": call_id,
                "agent_profanity": "Yes" if result["profanity"]["agent"] else "No",
                "customer_profanity": "Yes" if result["profanity"]["customer"] else "No",
                "compliance_violation": "Yes" if not result["privacy_compliance"]["verification_done"] else "No",
                "silence_pct": result["call_metrics"]["silence_pct"],
                "overtalk_pct": result["call_metrics"]["overtalk_pct"]
            }
            for call_id, result in self.results.items()
        ])
        df.to_csv(output_file, index=False)
        return f"Results exported to {output_file}"


def main():
    analyzer = CallAnalyzer()

    json_file = "conversation.json"  # Replace with your actual file path
    with open(json_file, "r") as file:
        conversation = json.load(file)

    call_id = os.path.basename(json_file).replace(".json", "")
    result = analyzer.analyze_call(conversation, call_id)

    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()

