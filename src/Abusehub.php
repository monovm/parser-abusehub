<?php

namespace AbuseIO\Parsers;

use SplFileObject;
use AbuseIO\Models\Incident;

/**
 * Class Abusehub
 * @package AbuseIO\Parsers
 */
class Abusehub extends Parser
{
    /**
     * Create a new Abusehub instance
     *
     * @param \PhpMimeMailParser\Parser phpMimeParser object
     * @param array $arfMail array with ARF detected results
     */
    public function __construct($parsedMail, $arfMail)
    {
        // Call the parent constructor to initialize some basics
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse attachments
     *
     * @return array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        foreach ($this->parsedMail->getAttachments() as $attachment) {
            // Only use the Abusehub formatted reports, skip all others
            if (preg_match(config("{$this->configBase}.parser.report_file"), $attachment->getFilename())) {
                // Create temporary working environment for the parser ($this->tempPath, $this->fs)
                $this->createWorkingDir();
                file_put_contents($this->tempPath . $attachment->getFilename(), $attachment->getContent());

                $csvFile = new SplFileObject($this->tempPath . $attachment->getFilename());
                $csvFile->setFlags(
                    SplFileObject::READ_CSV | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE
                );
                $csvFile->setCsvControl(',');
                $headers = null;

                // Loop through all csv reports
                foreach ($csvFile as $row) {
                    if ($row === null || $row === false || (is_array($row) && count($row) === 1 && $row[0] === null)) {
                        continue;
                    }

                    if ($headers === null) {
                        $headers = $row;
                        continue;
                    }

                    $report = [];
                    foreach ($headers as $i => $head) {
                        if ($head === null || $head === '') {
                            continue;
                        }
                        $report[$head] = array_key_exists($i, $row) ? $row[$i] : null;
                    }
                    if (!empty($report['report_type'])) {
                        $this->feedName = $report['report_type'];

                        // If feed is known and enabled, validate data and save report
                        if ($this->isKnownFeed() && $this->isEnabledFeed()) {
                            // Sanity check
                            if ($this->hasRequiredFields($report) === true) {
                                // incident has all requirements met, filter and add!
                                $report = $this->applyFilters($report);

                                $incident = new Incident();
                                $incident->source      = config("{$this->configBase}.parser.name");
                                $incident->source_id   = false;
                                $incident->ip          = $report['src_ip'];
                                $incident->domain      = false;
                                $incident->class       = config("{$this->configBase}.feeds.{$this->feedName}.class");
                                $incident->type        = config("{$this->configBase}.feeds.{$this->feedName}.type");
                                $incident->timestamp   = strtotime($report['event_date'] .' '. $report['event_time']);
                                $incident->information = json_encode($report);

                                $this->incidents[] = $incident;
                            }
                        }
                    } else {
                        // We cannot parse this report, since we haven't detected a report_type.
                        $this->warningCount++;
                    }
                } // end foreach: loop through csv lines
            } // end if: found report file to parse
        } // end foreach: loop through attachments

        return $this->success();
    }
}
