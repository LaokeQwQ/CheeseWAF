package semantic
import ("context";"regexp";"strings"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder")
var xxePatterns=[]*regexp.Regexp{
	regexp.MustCompile(`(?i)<!DOCTYPE\s+\w+\s*\[.*<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)\s+["'][^"']+["']`),
	regexp.MustCompile(`(?i)<!ENTITY\s+%\s+\w+\s+SYSTEM\s+["'][^"']+["']`),
	regexp.MustCompile(`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["'](?:file|php|expect|http|https|ftp)://`)}
type XXEDetector struct{mode string}
func NewXXEDetector(mode string)*XXEDetector{if mode==""{mode="block"};return &XXEDetector{mode:mode}}
func(d *XXEDetector)ID()string{return "semantic.xxe"}
func(d *XXEDetector)Name()string{return "XXE Semantic Detector"}
func(d *XXEDetector)Priority()int{return 360}
func(d *XXEDetector)Detect(_ context.Context,reqCtx *engine.RequestContext)(*engine.DetectionResult,error){
	payload:=requestText(reqCtx);candidates:=[]string{payload,decoder.Decode(payload).Text}
	for _,c:=range candidates{trimmed:=strings.TrimSpace(c)
		for _,p:=range xxePatterns{if p.MatchString(trimmed){return &engine.DetectionResult{Detected:true,DetectorID:d.ID(),Category:"xxe",Severity:engine.SeverityCritical,Action:actionForMode(d.mode),Message:"XXE injection detected",Confidence:0.90,Payload:trimmed},nil}}}
	return nil,nil}
