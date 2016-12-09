<?php

/**
 * @file
 * Module used to create the PDF upload step for Scholar.
 */

/**
 * Gets the upload form.
 *
 * @param array $form
 *   The Drupal form definition.
 * @param array $form_state
 *   The Drupal form state.
 *
 * @return array
 *   The Drupal form definition.
 */
function islandora_scholar_pdf_upload_form(array $form, array &$form_state)
{
    $upload_size = min((int)ini_get('post_max_size'), (int)ini_get('upload_max_filesize'));

    // Pull document versions from the module settings if available.
    $document_versions = get_document_versions();

    // Pull use permissions from the module settings if available.
    $use_permissions = get_use_permissions();

    $form['upload_pdf_checkbox'] = array(
        '#type' => 'checkbox',
        '#title' => t('Would you like to include a PDF document for this citation?'),
    );
    $form['upload_document'] = array(
        '#type' => 'fieldset',
        '#title' => t('Upload Document'),
        '#states' => array(
            'visible' => array(
                ':input[name="upload_pdf_checkbox"]' => array('checked' => TRUE),
            ),
        ),
    );
    $form['upload_document']['file'] = array(
        '#type' => 'managed_file',
        '#title' => 'PDF file',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array('pdf'),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        ),
    );
    $form['upload_document']['version'] = array(
        '#type' => 'hidden',
        '#title' => t('Document Version'),
//    '#options' => $document_versions,
        '#value' => 'PUBLISHED',
    );
    $form['upload_document']['usage'] = array(
        '#type' => 'hidden',
        '#title' => t('Use Permission'),
        '#value' => 'author',
//        '#options' => $use_permissions,
    );
    $form['upload_document']['certifying'] = array(
        '#type' => 'checkboxes',
        '#title' => t('Certify'),
        '#options' => array(
            'certify' => t('I certify that I have the right to upload this version.'),
        ),
    );
    $form['supply_supplemental'] = array(
        '#type' => 'checkbox',
        '#title' => t('Would you like to include supplemental files with this Electronic Thesis or Dissertation?'),
    );
    $form['upload_supplemental'] = array(
        '#type' => 'fieldset',
        '#title' => t('Upload Supplemental Files'),
        '#states' => array(
            'visible' => array(
                ':input[name="supply_supplemental"]' => array('checked' => TRUE),
            ),
        ),
    );
    $form['upload_supplemental']['set1']['file1'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 1',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        ),
    );
    $form['upload_supplemental']['set1']['file2'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 2',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        ),
    );
    $form['upload_supplemental']['set1']['file3'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 3',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        ),
    );
    $form['upload_supplemental']['set1']['file4'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 4',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        ),
    );
    $form['upload_supplemental']['set1']['file5'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 5',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        ),
    );
    $form['upload_supplemental']['supply_supplemental2'] = array(
        '#type' => 'checkbox',
        '#title' => t('Would you like to include additional supplemental files with this ETD?'),
        $form['upload_supplemental2'] = array(
            '#type' => 'fieldset',
            '#title' => t('Additional Supplemental Files'),
            '#states' => array(
                'visible' => array(
                    ':input[name="supply_supplemental2"]' => array('checked' => TRUE),
                ),
            ),
        ),
    );
    $form['upload_supplemental2']['set2']['file6'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 6',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        ),
    );
    $form['upload_supplemental2']['set2']['file7'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 7',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        ),
    );
    $form['upload_supplemental2']['set2']['file8'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 8',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        ),
    );
    $form['upload_supplemental2']['set2']['file9'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 9',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        ),
    );
    $form['upload_supplemental2']['set2']['file10'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 10',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        ),
    );
    $form['upload_supplemental2']['supply_supplemental3'] = array(
        '#type' => 'checkbox',
        '#title' => t('Would you like to include additional supplemental files with this ETD (Part II)?'),
        $form['upload_supplemental3'] = array(
            '#type' => 'fieldset',
            '#title' => t('Additional Supplemental Files, Part II'),
            '#states' => array(
                'visible' => array(
                    ':input[name="supply_supplemental3"]' => array('checked' => TRUE),
                ),
            ),
        ),
    );
    $form['upload_supplemental3']['set3']['file11'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 11',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        )
    );
    $form['upload_supplemental3']['set3']['file12'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 12',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        )
    );
    $form['upload_supplemental3']['set3']['file13'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 13',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        )
    );
    $form['upload_supplemental3']['set3']['file14'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 14',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        )
    );
    $form['upload_supplemental3']['set3']['file15'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 15',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        )
    );
    $form['upload_supplemental3']['supply_supplemental4'] = array(
        '#type' => 'checkbox',
        '#title' => t('Would you like to include additional supplemental files with this ETD (Part III)?'),
        $form['upload_supplemental4'] = array(
            '#type' => 'fieldset',
            '#title' => t('Additional Supplemental Files, Part III'),
            '#states' => array(
                'visible' => array(
                    ':input[name="supply_supplemental4"]' => array('checked' => TRUE),
                ),
            ),
        ),
    );
    $form['upload_supplemental4']['set3']['file16'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 16',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        )
    );
    $form['upload_supplemental4']['set3']['file17'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 17',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        )
    );
    $form['upload_supplemental4']['set3']['file18'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 18',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        )
    );
    $form['upload_supplemental4']['set3']['file19'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 19',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        )
    );
    $form['upload_supplemental4']['set3']['file20'] = array(
        '#type' => 'managed_file',
        '#title' => 'Supplemental File 20',
        '#upload_location' => 'temporary://',
        '#upload_validators' => array(
            'file_validate_extensions' => array(),
            'file_validate_size' => array($upload_size * 1024 * 1024),
        )
    );
    $form['upload_supplemental4']['supply_supplemental5'] = array(
        '#type' => 'checkbox',
        '#title' => t('Would you like to continue adding supplemental files? Please contact admin-at-trace @ trace for assistance'),
    );
    return $form;
}

/**
 * Validation for the Islandora Scholar PDF upload form.
 *
 * @param array $form
 *   The Drupal form definition.
 * @param array $form_state
 *   The Drupal form state.
 */
function islandora_scholar_pdf_upload_form_validate($form, $form_state)
{
    if ($form_state['values']['upload_pdf_checkbox']) {
        if (empty($form_state['values']['file'])) {
            form_set_error('file', t('A file must be uploaded!'));
        }
        if (empty($form_state['values']['version'])) {
            form_set_error('version', t('A document version must be selected!'));
        }
        if (empty($form_state['values']['usage'])) {
            form_set_error('usage', t('A usage permission must be selected!'));
        }
        if (empty($form_state['values']['certifying']['certify'])) {
            form_set_error('certifying', t('You must certify that you have the right to upload this PDF!'));
        }
    }
}

/**
 * Upload form Submit handler, adds PDF datastream.
 *
 * Also updates the MODS usage and version for the PDF datastream.
 *
 * @param array $form
 *   The Drupal form definition.
 * @param array $form_state
 *   The Drupal form state.
 */
function islandora_scholar_pdf_upload_form_submit(array $form, array &$form_state)
{
    if ($form_state['values']['upload_pdf_checkbox']) {
        $object = islandora_ingest_form_get_object($form_state);
        module_load_include('inc', 'islandora_scholar', 'includes/upload.tab');
        $file = file_load($form_state['values']['file']);
        $datastream = $object->constructDatastream('PDF', 'M');
        $datastream->label = $file->filename;
        $datastream->mimetype = 'application/pdf';
        $datastream->setContentFromFile($file->uri, FALSE);
        $object->ingestDatastream($datastream);
        islandora_scholar_add_usage_and_version_elements_to_mods($object, $form_state['values']['usage'], $form_state['values']['version']);
    }
    if ($form_state['values']['supply_supplemental']) {
        $object = islandora_ingest_form_get_object($form_state);
        module_load_include('inc', 'islandora_scholar', 'includes/upload.tab');
        // SUPPL_0
        if ($form_state['values']['file1']) {
            $file1 = file_load($form_state['values']['file1']);
            $datastream = $object->constructDatastream('SUPPL_0', 'M');
            $datastream->label = $file1->filename;
            $datastream->mimetype = $file1->filemime;
            $datastream->setContentFromFile($file1->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        // SUPPL_1
        if ($form_state['values']['file2']) {
            $file2 = file_load($form_state['values']['file2']);
            $datastream = $object->constructDatastream('SUPPL_1', 'M');
            $datastream->label = $file2->filename;
            $datastream->mimetype = $file2->filemime;
            $datastream->setContentFromFile($file2->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        // SUPPL_2
        if ($form_state['values']['file3']) {
            $file3 = file_load($form_state['values']['file3']);
            $datastream = $object->constructDatastream('SUPPL_2', 'M');
            $datastream->label = $file3->filename;
            $datastream->mimetype = $file3->filemime;
            $datastream->setContentFromFile($file3->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        // SUPPL_3
        if ($form_state['values']['file4']) {
            $file4 = file_load($form_state['values']['file4']);
            $datastream = $object->constructDatastream('SUPPL_3', 'M');
            $datastream->label = $file4->filename;
            $datastream->mimetype = $file4->filemime;
            $datastream->setContentFromFile($file4->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        // SUPPLE_4
        if ($form_state['values']['file5']) {
            $file5 = file_load($form_state['values']['file5']);
            $datastream = $object->constructDatastream('SUPPL_4', 'M');
            $datastream->label = $file5->filename;
            $datastream->mimetype = $file5->filemime;
            $datastream->setContentFromFile($file5->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
    }
    if ($form_state['values']['supply_supplemental2']) {
        $object = islandora_ingest_form_get_object($form_state);
        module_load_include('inc', 'islandora_scholar', 'includes/upload.tab');
        // SUPPL_5
        if ($form_state['values']['file6']) {
            $file6 = file_load($form_state['values']['file6']);
            $datastream = $object->constructDatastream('SUPPL_5', 'M');
            $datastream->label = $file6->filename;
            $datastream->mimetype = $file6->filemime;
            $datastream->setContentFromFile($file6->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        if ($form_state['values']['file7']) {
            $file7 = file_load($form_state['values']['file7']);
            $datastream = $object->constructDatastream('SUPPL_6', 'M');
            $datastream->label = $file7->filename;
            $datastream->mimetype = $file7->filemime;
            $datastream->setContentFromFile($file7->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        if ($form_state['values']['file8']) {
            $file8 = file_load($form_state['values']['file8']);
            $datastream = $object->constructDatastream('SUPPL_7', 'M');
            $datastream->label = $file8->filename;
            $datastream->mimetype = $file8->filemime;
            $datastream->setContentFromFile($file8->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        if ($form_state['values']['file9']) {
            $file9 = file_load($form_state['values']['file9']);
            $datastream = $object->constructDatastream('SUPPL_8', 'M');
            $datastream->label = $file9->filename;
            $datastream->mimetype = $file9->filemime;
            $datastream->setContentFromFile($file9->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        if ($form_state['values']['file10']) {
            $file10 = file_load($form_state['values']['file10']);
            $datastream = $object->constructDatastream('SUPPL_9', 'M');
            $datastream->label = $file10->filename;
            $datastream->mimetype = $file10->filemime;
            $datastream->setContentFromFile($file10->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
    }
    if ($form_state['values']['supply_supplemental3']) {
        $object = islandora_ingest_form_get_object($form_state);
        module_load_include('inc', 'islandora_scholar', 'includes/upload.tab');
        // SUPPL_5
        if ($form_state['values']['file11']) {
            $file11 = file_load($form_state['values']['file11']);
            $datastream = $object->constructDatastream('SUPPL_10', 'M');
            $datastream->label = $file11->filename;
            $datastream->mimetype = $file11->filemime;
            $datastream->setContentFromFile($file11->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        if ($form_state['values']['file12']) {
            $file12 = file_load($form_state['values']['file12']);
            $datastream = $object->constructDatastream('SUPPL_11', 'M');
            $datastream->label = $file12->filename;
            $datastream->mimetype = $file12->filemime;
            $datastream->setContentFromFile($file12->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        if ($form_state['values']['file13']) {
            $file13 = file_load($form_state['values']['file13']);
            $datastream = $object->constructDatastream('SUPPL_12', 'M');
            $datastream->label = $file13->filename;
            $datastream->mimetype = $file13->filemime;
            $datastream->setContentFromFile($file13->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        if ($form_state['values']['file14']) {
            $file14 = file_load($form_state['values']['file14']);
            $datastream = $object->constructDatastream('SUPPL_13', 'M');
            $datastream->label = $file14->filename;
            $datastream->mimetype = $file14->filemime;
            $datastream->setContentFromFile($file14->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        if ($form_state['values']['file15']) {
            $file15 = file_load($form_state['values']['file15']);
            $datastream = $object->constructDatastream('SUPPL_14', 'M');
            $datastream->label = $file15->filename;
            $datastream->mimetype = $file15->filemime;
            $datastream->setContentFromFile($file15->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
    }
    if ($form_state['values']['supply_supplemental4']) {
        $object = islandora_ingest_form_get_object($form_state);
        module_load_include('inc', 'islandora_scholar', 'includes/upload.tab');
        // SUPPL_5
        if ($form_state['values']['file16']) {
            $file16 = file_load($form_state['values']['file16']);
            $datastream = $object->constructDatastream('SUPPL_15', 'M');
            $datastream->label = $file16->filename;
            $datastream->mimetype = $file16->filemime;
            $datastream->setContentFromFile($file16->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        if ($form_state['values']['file17']) {
            $file17 = file_load($form_state['values']['file17']);
            $datastream = $object->constructDatastream('SUPPL_16', 'M');
            $datastream->label = $file17->filename;
            $datastream->mimetype = $file17->filemime;
            $datastream->setContentFromFile($file17->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        if ($form_state['values']['file18']) {
            $file18 = file_load($form_state['values']['file18']);
            $datastream = $object->constructDatastream('SUPPL_17', 'M');
            $datastream->label = $file18->filename;
            $datastream->mimetype = $file18->filemime;
            $datastream->setContentFromFile($file18->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        if ($form_state['values']['file19']) {
            $file19 = file_load($form_state['values']['file19']);
            $datastream = $object->constructDatastream('SUPPL_18', 'M');
            $datastream->label = $file19->filename;
            $datastream->mimetype = $file19->filemime;
            $datastream->setContentFromFile($file19->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
        if ($form_state['values']['file20']) {
            $file20 = file_load($form_state['values']['file20']);
            $datastream = $object->constructDatastream('SUPPL_19', 'M');
            $datastream->label = $file20->filename;
            $datastream->mimetype = $file20->filemime;
            $datastream->setContentFromFile($file20->uri, FALSE);
            $object->ingestDatastream($datastream);
        }
    }
}

/**
 * Undo submit handler for the PDF upload ingest step for Scholar.
 *
 * @param array $form
 *   The Drupal form definition.
 * @param array $form_state
 *   The Drupal form state.
 */
function islandora_scholar_pdf_upload_form_undo_submit(array $form, array &$form_state)
{
    $object = islandora_ingest_form_get_object($form_state);
    $object->purgeDatastream('PDF');
}
