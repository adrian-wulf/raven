package engine

import (
	"regexp"
	"strings"
)

// ValidatorPatterns contains known validation patterns per language
var ValidatorPatterns = map[string][]string{
	"javascript": {
		`typeof\s+\w+\s*===?\s*['"]string['"]`,
		`typeof\s+\w+\s*===?\s*['"]number['"]`,
		`typeof\s+\w+\s*===?\s*['"]boolean['"]`,
		`Array\.isArray\s*\(`,
		`Number\.isFinite\s*\(`,
		`Number\.isInteger\s*\(`,
		`joi\.`, `yup\.`, `zod\.`, `validator\.`,
		`express-validator`, `celebrate\s*\(`, `Joi\.`,
		`\.match\s*\([^)]+\)`, `\.test\s*\(`, `RegExp\s*\(`,
		`\.length\s*[<>=!]`, `\.includes\s*\(`,
	},
	"python": {
		`isinstance\s*\(`, `type\s*\(\s*\w+\s*\)\s*is`,
		`pydantic`, `marshmallow`, `cerberus`, `voluptuous`,
		`wtforms`, `django\.forms`, `rest_framework\.serializers`,
		`re\.match\s*\(`, `re\.search\s*\(`, `re\.fullmatch\s*\(`,
		`str\.isalnum`, `str\.isalpha`, `str\.isdigit`,
		`\.startswith\s*\(`, `\.endswith\s*\(`,
		`len\s*\([^)]+\)\s*[<>=!]`,
	},
	"go": {
		`\.\([*\w]+\)`, `reflect\.TypeOf`,
		`go-playground/validator`, `ozzo-validation`, `govalidator`,
		`regexp\.Match`, `strings\.HasPrefix`, `strings\.Contains`,
		`strconv\.`, `len\s*\([^)]+\)\s*[<>=!]`,
	},
	"java": {
		`@NotNull`, `@NotEmpty`, `@NotBlank`, `@Valid`, `@Pattern`,
		`@Size`, `@Min`, `@Max`, `@Email`, `@Positive`,
		`Validator\.`, `ValidationUtils`,
		`Pattern\.compile\s*\(`, `String\.matches\s*\(`,
		`instanceof\s+\w+`,
	},
	"php": {
		`is_string\s*\(`, `is_int\s*\(`, `is_array\s*\(`, `is_numeric\s*\(`,
		`filter_var\s*\(`, `FILTER_VALIDATE_`,
		`Validator::`, `Form::`, `Request::validate`,
		`preg_match\s*\(`, `preg_match_all\s*\(`,
		`validate\s*\(\s*\[`, `Validator::make`,
	},
	"ruby": {
		`\.is_a\?`, `\.kind_of\?`, `\.instance_of\?`,
		`validates_`, `ActiveModel::Validations`,
		`\.match\?\s*\(`, `=~`, `Regexp\.new`,
	},
	"csharp": {
		`\[Required\]`, `\[StringLength\]`, `\[Range\]`, `\[RegularExpression\]`,
		`\[EmailAddress\]`, `\[MinLength\]`, `\[MaxLength\]`,
		`RuleFor\s*\(`, `FluentValidation`,
		`Regex\.`, `Regex\.IsMatch`,
	},
	"rust": {
		`\.parse\s*::<`, `TryFrom`, `FromStr`, `match\s+\w+\s*\{`,
		`validator::`, `garde::`, `validate\s*\(`,
		`Regex::new\s*\(`, `regex::`,
	},
	"kotlin": {
		`@NotNull`, `@Nullable`, `require\s*\(`, `check\s*\(`,
		`requireNotNull`, `checkNotNull`, `@Valid`,
	},
	"swift": {
		`guard\s+let`, `if\s+let`, `as\?\s+`, `is\s+\w+`,
		`guard\s+\w+\s*!=\s*nil`, `try\?`,
	},
}

// IsValidated checks if the given line is within a validated scope
func IsValidated(content []byte, line int, lang string) bool {
	patterns, ok := ValidatorPatterns[lang]
	if !ok {
		return false
	}
	lines := strings.Split(string(content), "\n")
	if line < 1 || line > len(lines) {
		return false
	}
	idx := line - 1
	for i := max(0, idx-10); i <= idx; i++ {
		for _, p := range patterns {
			re := regexp.MustCompile(p)
			if re.MatchString(lines[i]) {
				return true
			}
		}
	}
	return false
}

// ValidationStrength returns a score 0.0-1.0 based on validation density
func ValidationStrength(content []byte, lang string) float64 {
	patterns, ok := ValidatorPatterns[lang]
	if !ok {
		return 0
	}
	lines := strings.Split(string(content), "\n")
	validCount := 0
	for _, line := range lines {
		for _, p := range patterns {
			re := regexp.MustCompile(p)
			if re.MatchString(line) {
				validCount++
				break
			}
		}
	}
	ratio := float64(validCount) / float64(len(lines))
	if ratio > 0.3 {
		return 1.0
	}
	return ratio / 0.3
}
