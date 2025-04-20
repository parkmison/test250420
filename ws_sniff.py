from scapy.all import rdpcap
import os
import re

from scapy.contrib.skinny import msgid

PCAP_FILE = "mafia42_ws.pcapng"
OUTPUT_FILE = "megaphone_log.txt"
seen_messages = set()

text_regex = r"([가-힣]+)[ ]?: ([가-힣a-zA-Z0-9?!@\+\-\*\/\=\\🧡💛💙💜💚💗💕💖💞❣️❤️👍👎😂🤣😭😭😍🤔🔥🌟⭐ ]+[가-힣?!@])"


if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            print("[✔️ 확인함]", line.strip())
            seen_messages.add(line)
else:
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        pass

# def is_clean_text(s):
#     # 한글, 영어, 숫자 포함되었는지 필터링
#     return (
#         bool(
#             re.search(
#                 text_regex,
#                 s,
#             )
#         )
#         and len(s.strip()) >= 6
#     )


def clean_text(s):
    # 제어 문자 제거 및 공백 정리
    s = s.replace("\x00", "").replace("\x1f", "").strip()
    return re.match(text_regex, s)[0]


def extract_text_from_pcap(pcap_path):
    if not os.path.exists(pcap_path):
        print("[!] pcap 파일 없음")
        return

    packets = rdpcap(pcap_path)
    new_messages = []

    for pkt in packets:
        if pkt.haslayer("Raw"):
            raw = bytes(pkt["Raw"].load)
            try:
                text = raw.decode("utf-8", errors="ignore")
                if not text:
                    print("[!] text 없음")
                    continue
                founds = re.findall(text_regex, text)
                if founds:
                    for (name, content) in founds:
                        line = f"{name} : {content}"
                        if line not in seen_messages:
                            seen_messages.add(line)
                            new_messages.append(line)
            except Exception as e:
                pass

    if new_messages:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            for msg in new_messages:
                f.write(msg + "\n")
                print("[✔️ 추출됨]", msg)


print("-" * 10)
# 한 번만 실행

extract_text_from_pcap(PCAP_FILE)

