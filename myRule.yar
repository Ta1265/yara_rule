import "pe"
import "math"

rule myRule {
  condition:
    uint16(0) == 0x5a4d and
    pe.number_of_sections < 1 or pe.number_of_sections > 8 or
    pe.characteristics & pe.RELOCS_STRIPPED == 1 or
    pe.characteristics & pe.BYTES_REVERSED_HI == 1 or
    pe.characteristics & pe.BYTES_REVERSED_LO == 1 or
    math.entropy(0, filesize) > 7.0 or
    for any section in pe.sections: ((section.virtual_size\section.raw_data_size) > 10) or
		(pe.entry_point\filesize) > 2

}
